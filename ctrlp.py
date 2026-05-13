# coding: utf-8
# @author msm
# @category Search
# @menupath Search.Palette
# @toolbar

import re
import base64
import binascii
from ghidra.program.flatapi import FlatProgramAPI
from ghidra.program.model.symbol import SymbolType, SourceType
from ghidra.program.model.listing import BookmarkType
from ghidra.app.services import ConsoleService, CodeViewerService
from ghidra.util.task import TaskMonitor
from ghidra.app.script import GhidraScriptUtil, GhidraState
from ghidra.app.util.viewer.field import ListingColors
from javax.swing import JFrame, JTextField, JList, JScrollPane, SwingUtilities, JPanel, DefaultListCellRenderer, UIManager
from java.lang import Object, System, Thread
from java.awt import BorderLayout, Color, Font, GraphicsEnvironment, Window
from java.awt.event import KeyEvent
from java.util import Vector
from java.awt import Toolkit
from java.awt.datatransfer import StringSelection
from jpype import JProxy


try:
    long
except NameError:
    long = int

_SYMBOL_CACHE = {}
_SYMBOL_CACHE_ORDER = []
_SYMBOL_CACHE_LIMIT = 3


def _program_cache_key(program):
    try:
        ident = System.identityHashCode(program)
    except Exception:
        try:
            ident = id(program)
        except Exception:
            ident = 0
    path = "unknown"
    try:
        domain = program.getDomainFile()
        if domain:
            try:
                path = domain.getPathname()
            except Exception:
                path = str(domain)
    except Exception:
        try:
            path = str(program)
        except Exception:
            pass
    return (path, ident)


def _program_mod_number(program):
    try:
        return program.getModificationNumber()
    except Exception:
        return None


def _touch_symbol_cache(cache_key):
    try:
        _SYMBOL_CACHE_ORDER.remove(cache_key)
    except ValueError:
        pass
    _SYMBOL_CACHE_ORDER.append(cache_key)
    if len(_SYMBOL_CACHE_ORDER) > _SYMBOL_CACHE_LIMIT:
        old_key = _SYMBOL_CACHE_ORDER.pop(0)
        if old_key in _SYMBOL_CACHE:
            del _SYMBOL_CACHE[old_key]


def get_current_address():
    try:
        return currentAddress
    except NameError:
        codeViewerService = makeState().getTool().getService(CodeViewerService)
        if codeViewerService and codeViewerService.getCurrentLocation():
            return codeViewerService.getCurrentLocation().getAddress()
        return getCurrentProgram().getImageBase()


def matches(name, query):
    """Baby fuzzy matcher - splits query by whitespace, and matches
    if name contains every resulting element. For example,
    "aaa bbb ccc" matches "aaa ccc" but not "aaaccc" or "aaa ddd" """ 
    name = name.lower()
    query = query.lower()

    chunks = query.split()
    for c in chunks:
        # Special case - filtering by type, for example user searches for `wnd script`
        if c in ["fnc", "dat", "lbl", "bkm", "wnd", "act", "scr", "txt", "ref"]:
            if not name.startswith(c):
                return False

        ndx = name.find(c)
        if ndx < 0:
            return False
    return True


def makeState():
    """Creates a new (current) state object and returns it

    We can't just use getState(), because it's a snapshot of program state.
    For tool and project it doesn't matter. For program it also doesn't matter,
    but we need to remember to use getCurrentProgram() instead of currentProgram
    in the script code (the variable is also constant, while in some cases -
    like multitab windows - current project may change for a CtrlP window.
    Finally, selection changes all the time, so we need to update it here."""
    oldState = getState()

    codeViewerService = oldState.getTool().getService(CodeViewerService)
    if codeViewerService:
        currLocation = codeViewerService.getCurrentLocation()
        currSelection = codeViewerService.getCurrentSelection()
        currHighlight = codeViewerService.getListingPanel().getProgramHighlight()
    else:
        currLocation = oldState.getCurrentLocation()
        currSelection = oldState.getCurrentSelection()
        currHighlight = oldState.getCurrentHighlight()

    return GhidraState(
        oldState.getTool(),  # I think this can't change
        oldState.getProject(),  # I think this can't change
        getCurrentProgram(),
        currLocation,
        currSelection,
        currHighlight,
    )


def transientGoto(addr):
    """Goto, but without saving it in the history"""
    codeViewerService = makeState().getTool().getService(CodeViewerService)
    if codeViewerService:
        from ghidra.program.util import ProgramLocation
        codeViewerService.goTo(ProgramLocation(getCurrentProgram(), addr), True)
    else:
        # fallback
        goTo(addr)


def wrap_goto(addr):
    """This is a wrapper for goTo, returns a function that goToes to the addr

    the point is to capture addr in a closure (something that won't happen in a lambda"""
    return lambda: goTo(addr)


class ScriptExecutor(object):
    def __init__(self, script):
        self.script = script

    def execute(self):
        con = makeState().getTool().getService(ConsoleService)
        prov = GhidraScriptUtil.getProvider(self.script)
        inst = prov.getScriptInstance(self.script, con.getStdOut())
        inst.execute(makeState(), monitor, con.getStdOut())


class SymbolLoader(object):
    def __init__(self, parent):
        self.parent = parent

    def get_everything(self):
        everything = []
        everything += get_symbols()
        everything += get_component_providers()
        everything += get_bookmarks()
        everything += get_actions()
        everything += get_scripts()
        return everything

    def execute(self):
        try:
            symbols = self.get_everything()
        except:
            # uncomment this for debug info:
            # import traceback
            # state.getTool().getService(ConsoleService).println(traceback.format_exc())

            # BUG TODO FIXME
            # When Ghidra window is closed and then reopened, the references in the window stop making sense.
            # and this thread/wtf is in a broken state.
            # We should probably watch when ghidra window exits and then cleanup, but...
            # Just kill ourselves and let user try again.
            invoke_later(lambda: self.parent.dispose())
            return

        def refresh_data():
            ndx = self.parent.symbolList.getSelectedIndex()
            self.parent.updateList(self.parent.inputField.getText())
            self.parent.symbolList.setSelectedIndex(ndx)

        try:
            self.parent.symbols = symbols
            invoke_later(refresh_data)
        except Exception as e:
            print("Error loading symbols" + str(e))


def run_in_background(func, name=None):
    class _Runnable(object):
        def run(self):
            func()

    runnable = JProxy("java.lang.Runnable", inst=_Runnable())
    thread = Thread(runnable)
    if name:
        thread.setName(name)
    thread.setDaemon(True)
    thread.start()


def prettyPrintAddress(source):
    func_manager = getCurrentProgram().getFunctionManager()
    xref_func = func_manager.getFunctionContaining(source)
    if xref_func is None:
        codeunit = getCurrentProgram().getListing().getCodeUnitContaining(source)
        if codeunit is not None:
            text = "lbl {:x} {}".format(source.getOffset(), str(codeunit))
        else:
            text = "dat {:x}".format(source.getOffset())
    else:
        offset = source.subtract(xref_func.getEntryPoint())
        text = "fnc {}+{:x}".format(xref_func.getPrototypeString(True, False), offset)
    return text


def get_color(sym):
    kind = sym.text.split()[0]
    return {
        "fnc": ListingColors.FunctionColors.NAME,
        "dat": ListingColors.REGISTER,
        "lbl": ListingColors.MnemonicColors.NORMAL,
        "bkm": ListingColors.FunctionColors.VARIABLE,
        "wnd": ListingColors.CommentColors.REPEATABLE,
        "act": ListingColors.XrefColors.DEFAULT,
        "scr": ListingColors.MnemonicColors.OVERRIDE,
        "txt": ListingColors.MnemonicColors.NORMAL,
        "ref": ListingColors.REGISTER,
    }[kind]


def as_component_listener(listener):
    return JProxy("java.awt.event.ComponentListener", inst=listener)


def as_key_listener(listener):
    return JProxy("java.awt.event.KeyListener", inst=listener)


def as_document_listener(listener):
    return JProxy("javax.swing.event.DocumentListener", inst=listener)


def as_list_cell_renderer(renderer):
    return JProxy("javax.swing.ListCellRenderer", inst=renderer)


def invoke_later(func):
    class _Runnable(object):
        def run(self):
            func()

    SwingUtilities.invokeLater(JProxy("java.lang.Runnable", inst=_Runnable()))


class SymbolFilterWindow(object):
    def __init__(self, title, symbols):
        self.frame = JFrame(title)
        self.special_symbols = []
        self.symbols = symbols
        self.filtered_symbols = symbols
        self.initUI()
        self.selected_index = 0
        self.initial_address = get_current_address()
        # special_symbols are currently used in the "xref search mode" -
        # we are searching in them instead of self.symbols
        # Special search mode is enabled when self.special_symbols is not empty.
        # We don't reuse self.symbols for this, because populating self.symbols
        # takes time, and we want to have cached results when opening ctrl+p.

        self.recent_symbols = {}
        # keep track of recently used symbols. We want to show recent symbols
        # at the top of the search list, so it's easy to repeat the search.
        self.search_cache = {}
        self.search_cache_meta = {}
        self.search_cache_order = []
        self.search_cache_limit = 40
        self.last_search = None
        self.last_search_results = None
        self.last_search_truncated = False
        self.symbol_load_in_progress = False
        self.symbol_load_pending = False

    def __getattr__(self, attr):
        return getattr(self.frame, attr)

    def initUI(self):
        self.setSize(1200, 600)
        self.setResizable(False)
        self.setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE)
        self.getContentPane().setLayout(BorderLayout())

        me = self
        class MyComponentListener(object):
            def componentShown(self, event):
                codeViewerService = makeState().getTool().getService(CodeViewerService)
                if codeViewerService:
                    # We can't just use currentAddress because of a technicality:
                    # the variable in script is never updated and stays the same.
                    new_address = codeViewerService.getCurrentLocation().getAddress()
                    me.initial_address = new_address  # so we can cancel navigation
                me.special_symbols = []  # disable special search mode when showing
                me.inputField.setText("")  # clear the input field
                if me.symbols:
                    me.symbolList.setSelectedIndex(0)
                    me.symbolList.ensureIndexIsVisible(me.symbolList.getSelectedIndex())
                me.request_symbol_refresh()  # refresh symbols without blocking restore

            def componentHidden(self, event): pass
            def componentMoved(self, event): pass
            def componentResized(self, event): pass

        self.addComponentListener(as_component_listener(MyComponentListener()))

        inputPanel = JPanel(BorderLayout())
        self.inputField = JTextField()
        self.inputField.addKeyListener(as_key_listener(FilterKeyAdapter(self)))

        inputPanel.add(self.inputField, BorderLayout.CENTER)

        fontname = None
        FONTS = ["CaskaydiaMono NFM", "Monospaced"]
        for fontname in FONTS:
            g = GraphicsEnvironment.getLocalGraphicsEnvironment()
            if fontname in g.getAvailableFontFamilyNames():
                break
        assert fontname is not None

        font = Font(fontname, Font.PLAIN, 14)
        self.inputField.setFont(font)
        self.inputField.getDocument().addDocumentListener(as_document_listener(MyDocumentListener(self)))

        self.symbolList = JList(Vector([]))
        self.updateList("")
        self.symbolList.setCellRenderer(as_list_cell_renderer(SymbolCellRenderer(self)))
        self.symbolList.addKeyListener(as_key_listener(FilterKeyAdapter(self)))
        self.symbolList.setFont(font)

        self.scrollPane = JScrollPane(self.symbolList)

        self.getContentPane().add(inputPanel, BorderLayout.NORTH)
        self.getContentPane().add(self.scrollPane, BorderLayout.CENTER)

        if self.symbols:
            self.symbolList.setSelectedIndex(0)

        self.symbolList.setFocusable(False)

        self.inputField.requestFocusInWindow()

    def request_symbol_refresh(self):
        if self.symbol_load_in_progress:
            self.symbol_load_pending = True
            return

        self.symbol_load_in_progress = True
        self.symbol_load_pending = False

        def _load():
            try:
                SymbolLoader(self).execute()
            finally:
                def _finish():
                    self.symbol_load_in_progress = False
                    if self.symbol_load_pending:
                        self.request_symbol_refresh()

                invoke_later(_finish)

        run_in_background(_load, "ctrlp-symbol-loader")

    def _remember_search(self, cache_key, results, truncated):
        self.search_cache[cache_key] = results
        self.search_cache_meta[cache_key] = truncated
        try:
            self.search_cache_order.remove(cache_key)
        except ValueError:
            pass
        self.search_cache_order.append(cache_key)
        if len(self.search_cache_order) > self.search_cache_limit:
            old_key = self.search_cache_order.pop(0)
            if old_key in self.search_cache:
                del self.search_cache[old_key]
            if old_key in self.search_cache_meta:
                del self.search_cache_meta[old_key]

    def _byte_value(self, value):
        if isinstance(value, (int, long)):
            return value & 0xFF
        return ord(value) & 0xFF

    def _encode_search_bytes(self, text):
        try:
            raw = text.encode("latin1")
        except Exception:
            return None
        if isinstance(raw, str):
            return [ord(c) for c in raw]
        return list(raw)

    def _bytes_match(self, data, needle_bytes, ignore_case):
        if data is None or len(data) < len(needle_bytes):
            return False
        for i in range(len(needle_bytes)):
            data_b = self._byte_value(data[i])
            needle_b = needle_bytes[i]
            if ignore_case:
                if chr(data_b).lower() != chr(needle_b).lower():
                    return False
            else:
                if data_b != needle_b:
                    return False
        return True

    def _filter_search_results(self, entries, prev_needle, new_needle, ignore_case):
        if entries is None:
            return None
        if not new_needle.startswith(prev_needle) or len(new_needle) <= len(prev_needle):
            return None

        suffix = new_needle[len(prev_needle):]
        suffix_bytes = self._encode_search_bytes(suffix)
        if suffix_bytes is None:
            return None
        if not suffix_bytes:
            return entries

        prev_len = len(prev_needle)
        suffix_len = len(suffix_bytes)
        filtered = []
        for entry in entries:
            addr = entry.address
            if addr is None:
                continue
            try:
                data = getBytes(addr.add(prev_len), suffix_len)
            except Exception:
                data = None
            if self._bytes_match(data, suffix_bytes, ignore_case):
                filtered.append(entry)
        return filtered

    def _run_memory_search(self, needle, ignore_case):
        pattern = re.escape(needle)
        if ignore_case:
            pattern = "(?i)" + pattern

        flatapi = FlatProgramAPI(getCurrentProgram())
        occurs = list(flatapi.findBytes(getCurrentProgram().getMinAddress(), pattern, 101))

        truncated = False
        if len(occurs) > 100:
            occurs = occurs[:100]
            truncated = True

        mem = getCurrentProgram().getMemory()

        filtered_symbols = []
        for addr in occurs:
            start = addr.add(-10)
            rng = mem.getRangeContaining(addr)
            if start < rng.getMinAddress():
                start = rng.getMinAddress()

            context = getBytes(start, 130)
            if context is None:
                context = []
            context_text = "".join(
                chr(self._byte_value(b)) if 32 <= self._byte_value(b) < 127 else "."
                for b in context
            )
            filtered_symbols.append(SearchEntry(
                "dat " + str(addr) + " " + context_text,
                addr,
                wrap_goto(addr)
            ))
        return filtered_symbols, truncated

    def entries_by_search(self, needle, ignore_case):
        if not needle:
            return [SearchEntry(
                "dat (entering search mode)",
                None,
                lambda: None
            )]

        cache_key = (needle, ignore_case)
        cached = self.search_cache.get(cache_key)
        if cached is not None:
            self.last_search = cache_key
            self.last_search_results = cached
            self.last_search_truncated = self.search_cache_meta.get(cache_key, False)
            return cached

        if self.last_search and self.last_search[1] == ignore_case and not self.last_search_truncated:
            prev_needle = self.last_search[0]
            if prev_needle and needle.startswith(prev_needle):
                filtered = self._filter_search_results(
                    self.last_search_results, prev_needle, needle, ignore_case
                )
                if filtered is not None:
                    self._remember_search(cache_key, filtered, False)
                    self.last_search = cache_key
                    self.last_search_results = filtered
                    self.last_search_truncated = False
                    return filtered

        filtered_symbols, truncated = self._run_memory_search(needle, ignore_case)
        self._remember_search(cache_key, filtered_symbols, truncated)
        self.last_search = cache_key
        self.last_search_results = filtered_symbols
        self.last_search_truncated = truncated
        return filtered_symbols

    def quick_exec(self, command):
        try:
            result = eval(command, {"__builtins__": None}, {})
        except Exception as e:
            result = e

        def set_clipboard(txt):
            clipboard = Toolkit.getDefaultToolkit().getSystemClipboard()
            string_selection = StringSelection(txt)
            clipboard.setContents(string_selection, None)

        if isinstance(result, int) or isinstance(result, long):  # type: ignore (py2)
            strings = [
                "hex {:x}".format(result),
                "dec {}".format(result),
                "oct {:o}".format(result),
                "bin {:b}".format(result),
            ]
            func = getCurrentProgram().getFunctionManager().getFunctionContaining(toAddr(result))
            if func:
                off = toAddr(result).subtract(func.getEntryPoint())
                strings.append("sym " + func.getName() + ("+{:x}".format(off) if off else ""))
        elif isinstance(result, str):
            result_bytes = result.encode("utf-8")
            strings = [
                "str " + result,
                "hex " + binascii.hexlify(result_bytes).decode("ascii"),
                "base64 " + base64.b64encode(result_bytes).decode("ascii"),
            ]
            try:
                unhex = binascii.unhexlify(result.replace(" ", ""))
                strings.append("unhex " + unhex.decode("utf-8", "replace"))
            except (TypeError, ValueError, binascii.Error):
                pass
            try:
                unbase64 = base64.b64decode(result)
                strings.append("unbase64 " + unbase64.decode("utf-8", "replace"))
            except Exception:
                pass
        elif isinstance(result, list):
            strings = [str(r) for r in result]
        else:
            strings = [
                "str " + str(result)
            ]

        def set_clipboard_wrap(content):
            return lambda: set_clipboard(content)

        return [SearchEntry("txt " + s, None, set_clipboard_wrap(s[4:])) for s in strings]

    def get_order(self, sym):
        kind = sym.text.split()[0]
        primary_order = -self.recent_symbols.get(sym.text, -1)
        secondary_order = {
            "fnc": 0,
            "dat": 1,
            "lbl": 2,
            "bkm": 3,
            "wnd": 4,
            "act": 5,
            "scr": 6,
            "txt": 7,
            "ref": 8,
        }[kind]
        return (primary_order, secondary_order)

    def updateList(self, filter_text):
        if filter_text and filter_text[0] == '"':
            filtered_symbols = self.entries_by_search(filter_text[1:], False)
        elif filter_text and filter_text[0] == "'":
            filtered_symbols = self.entries_by_search(filter_text[1:], True)
        elif filter_text and filter_text[0] == "=":
            filtered_symbols = self.quick_exec(filter_text[1:])
        elif filter_text and filter_text[0] == "{":
            try:
                raw = binascii.unhexlify(filter_text[1:].replace(" ", ""))
                needle = raw.decode("latin1")
            except Exception:
                needle = ""
            filtered_symbols = self.entries_by_search(needle, False)
        else:
            symbols_to_search = self.symbols
            if self.special_symbols:
                symbols_to_search = self.special_symbols
            filtered_symbols = [
                sym for sym in symbols_to_search if matches(sym.text, filter_text)
            ]
            # we have to search first, because we can't skip high-priority symbols :(
            filtered_symbols = sorted(filtered_symbols, key=self.get_order)
            if len(filtered_symbols) > 1000:
                overflow = len(filtered_symbols) - 1000
                filtered_symbols = filtered_symbols[:1000]
                filtered_symbols.append(SearchEntry(
                    "txt and " + str(overflow) + " more...",
                    None,
                    lambda: None
                ))

        for sym in filtered_symbols:
            sym.has_bookmark_cache = None

        self.filtered_symbols = filtered_symbols
        self.symbolList.setListData(Vector([sym.text for sym in filtered_symbols]))

        if filtered_symbols:
            self.symbolList.setSelectedIndex(0)
        else:
            self.symbolList.clearSelection()

    def current_symbol(self):
        selected_index = self.symbolList.getSelectedIndex()
        if selected_index < 0:
            return None
        return self.filtered_symbols[selected_index]

    def updateRecent(self, selected_symbol):
        next_index = len(self.recent_symbols)
        self.recent_symbols[selected_symbol.text] = next_index

    def runSelectedAction(self):
        selected_symbol = self.current_symbol()
        if selected_symbol:
            self.updateRecent(selected_symbol)
            selected_symbol.action()

    def navigateToSelectedSymbol(self):
        selected_symbol = self.current_symbol()
        if selected_symbol and selected_symbol.address:
            transientGoto(selected_symbol.address)
        else:
            transientGoto(self.initial_address)

    def enterXrefMode(self):
        selected_symbol = self.current_symbol()
        if selected_symbol and selected_symbol.address:
            ref_manager = getCurrentProgram().getReferenceManager()
            self.special_symbols = []
            for ref in ref_manager.getReferencesTo(selected_symbol.address):
                source = ref.getFromAddress()

                text = prettyPrintAddress(source)
                sym = SearchEntry(
                    text,
                    source,
                    wrap_goto(source)
                )
                self.special_symbols.append(sym)
        self.updateList(self.inputField.getText())

    def bookmarkSelectedLocation(self):
        selected_symbol = self.current_symbol()
        if selected_symbol and selected_symbol.address:
            transaction = getCurrentProgram().startTransaction("Add Bookmark")

            # Flip the bookmarkstate
            if selected_symbol.has_bookmark:
                for bm in getCurrentProgram().getBookmarkManager().getBookmarks(selected_symbol.address):
                    getCurrentProgram().getBookmarkManager().removeBookmark(bm)
            else:
                getCurrentProgram().getBookmarkManager().setBookmark(
                    selected_symbol.address,
                    BookmarkType.NOTE,
                    "CtrlP",
                    "Quick bookmark. Query: " + self.inputField.getText()
                )

            selected_symbol.has_bookmark_cache = not selected_symbol.has_bookmark_cache

            getCurrentProgram().endTransaction(transaction, True)

            # Update the bookmark "star"
            ndx = self.symbolList.getSelectedIndex()
            self.updateList(self.inputField.getText())
            self.symbolList.setSelectedIndex(ndx)

    def copyToClipboard(self):
        selected_symbol = self.current_symbol()
        if selected_symbol:
            clipboard = Toolkit.getDefaultToolkit().getSystemClipboard()
            string_selection = StringSelection(selected_symbol.text)
            clipboard.setContents(string_selection, None)

    def copyAddressToClipboard(self):
        selected_symbol = self.current_symbol()
        if selected_symbol and selected_symbol.address:
            clipboard = Toolkit.getDefaultToolkit().getSystemClipboard()
            string_selection = StringSelection("0x" + str(selected_symbol.address))
            clipboard.setContents(string_selection, None)

    def goToFirstXRef(self):
        success = False
        selected_symbol = self.current_symbol()
        if selected_symbol and selected_symbol.address:
            ref_manager = getCurrentProgram().getReferenceManager()
            if ref_manager.getReferenceCountTo(selected_symbol.address) > 0:
                goTo(ref_manager.getReferencesTo(selected_symbol.address).next().getFromAddress())
                success = True
        return success

    def cancelNavigation(self):
        goTo(self.initial_address)


class MyDocumentListener(object):
    def __init__(self, parent):
        self.parent = parent

    def insertUpdate(self, e): self.update()
    def removeUpdate(self, e): self.update()
    def changedUpdate(self, e): self.update()
    def update(self):
        self.parent.updateList(self.parent.inputField.getText())


class FilterKeyAdapter(object):
    def __init__(self, parent):
        self.parent = parent

    def keyTyped(self, event):
        pass

    def keyReleased(self, event):
        pass

    def navigate(self, diff):
        symlist = self.parent.symbolList
        curr_pos = symlist.getSelectedIndex()
        curr_pos += diff
        if curr_pos < 0:
            curr_pos = 0
        if curr_pos >= symlist.getModel().getSize():
            curr_pos = symlist.getModel().getSize() - 1
        symlist.setSelectedIndex(curr_pos)
        symlist.ensureIndexIsVisible(symlist.getSelectedIndex())
        self.parent.navigateToSelectedSymbol()

    def keyPressed(self, event):
        if event.isControlDown() and event.getKeyCode() == KeyEvent.VK_ENTER:
            if self.parent.goToFirstXRef():
                self.parent.setVisible(False)
        elif event.getKeyCode() == KeyEvent.VK_ENTER:
            self.parent.setVisible(False)
            self.parent.runSelectedAction()
        elif event.getKeyCode() == KeyEvent.VK_UP:
            self.navigate(-1)
        elif event.getKeyCode() == KeyEvent.VK_DOWN:
            self.navigate(1)
        elif event.getKeyCode() == KeyEvent.VK_ESCAPE:
            if self.parent.special_symbols:
                # If we are in a special mode, clean it instead of closing entirely
                self.parent.special_symbols = []
                self.parent.updateList(self.parent.inputField.getText())
            else:
                self.parent.cancelNavigation()
                self.parent.setVisible(False)
        elif event.getKeyCode() == KeyEvent.VK_PAGE_DOWN:
            self.navigate(20)
        elif event.getKeyCode() == KeyEvent.VK_PAGE_UP:
            self.navigate(-20)
        elif event.getKeyCode() == KeyEvent.VK_END:
            self.navigate(2**30)
        elif event.getKeyCode() == KeyEvent.VK_HOME:
            self.navigate(-2**30)
        elif event.isControlDown() and event.getKeyCode() == KeyEvent.VK_D:
            self.parent.bookmarkSelectedLocation()
        elif event.isControlDown() and event.getKeyCode() == KeyEvent.VK_R:
            self.parent.enterXrefMode()
        elif event.isControlDown() and event.isShiftDown() and event.getKeyCode() == KeyEvent.VK_C:
            self.parent.copyAddressToClipboard()
        elif event.isControlDown() and event.getKeyCode() == KeyEvent.VK_C:
            self.parent.copyToClipboard()
        elif event.isControlDown() and event.getKeyCode() == KeyEvent.VK_Q:
            self.parent.dispose()
            System.gc()


class SymbolCellRenderer(object):
    def __init__(self, parent):
        self.window = parent
        self.default_renderer = DefaultListCellRenderer()

    def getListCellRendererComponent(self, list, value, index, isSelected, cellHasFocus):
        component = self.default_renderer.getListCellRendererComponent(
            list, value, index, isSelected, cellHasFocus)

        if 0 <= index < len(self.window.filtered_symbols):
            symbol = self.window.filtered_symbols[index]
            component.setForeground(symbol.color)

        return component


class SearchEntry:
    def __init__(self, text, address, action):
        self.raw_text = text
        self.address = address
        self.action = action
        self.has_bookmark_cache = None

    @property
    def color(self):
        return get_color(self)

    @property
    def text(self):
        if self.has_bookmark:
            return self.raw_text + u" [*]"
        return self.raw_text

    @property
    def has_bookmark(self):
        if self.has_bookmark_cache is None:
            self.has_bookmark_cache = self.address and len(getCurrentProgram().getBookmarkManager().getBookmarks(self.address)) > 0
        return self.has_bookmark_cache


def data_symbol_entry(sym):
    listing = getCurrentProgram().getListing()
    data = listing.getDataAt(sym.getAddress())
    addr = toAddr(sym.getAddress().getOffset())
    if data is not None:
        textrepr = data.getDefaultValueRepresentation()
        if len(textrepr) > 80:
            textrepr = textrepr[:80]
        if textrepr:
            textrepr = " (" + textrepr + ")"
        return SearchEntry(
            "dat " + data.getDataType().displayName + " " + sym.getName() + textrepr,
            addr,
            lambda: goTo(addr)
        )

    return SearchEntry(
        "lbl " + sym.getName(),
        addr,
        lambda: goTo(addr)
    )


def function_symbol_entry(sym):
    listing = getCurrentProgram().getListing()
    func = listing.getFunctionAt(sym.getAddress())
    addr = toAddr(sym.getAddress().getOffset())
    return SearchEntry(
        "fnc " + func.getPrototypeString(True, False),
        addr,
        lambda: goTo(addr)
    )


def action_entry(context, act):
    def execme():
        act.actionPerformed(context)

    suffix = ""
    if act.keyBinding:
        binding = str(act.keyBinding)
        binding = binding.replace("pressed ", "")
        binding = binding.replace(" ", "+")
        # This will produce things like ctrl+shift+alt+A.
        # I prefer emacs notation, so C-S-M-a, but I guess not everyone knows it.
        suffix = " (" + binding + ")"

    return SearchEntry(
        "act " + act.name + suffix,
        None,
        execme
    )


def run_script(scr_file):
    scr = GhidraScriptUtil.findScriptByName(scr_file.getName())
    ScriptExecutor(scr).execute()


def script_entry(scr):
    return SearchEntry(
        "scr " + scr.getName(),
        None,
        lambda: run_script(scr),
    )


def component_provider_entry(cp):
    def show_and_focus():
        makeState().getTool().showComponentProvider(cp, True)
        cp.toFront()

    return SearchEntry(
        "wnd " + str(cp),
        None,
        show_and_focus
    )


def bookmark_entry(bookmark):
    addr = toAddr(bookmark.getAddress().getOffset())

    category = bookmark.getCategory()
    if category:
        category = " (" + category + ")"
    return SearchEntry(
        "bkm " + str(bookmark.getComment()) + category,
        addr,
        lambda: goTo(addr)
    )


def get_actions():
    prov = makeState().getTool().getActiveComponentProvider()
    if prov is None:
        return []

    symbols = []
    context = prov.getActionContext(None)
    for act in makeState().getTool().getAllActions():
        if not act.getContextClass().isAssignableFrom(context.getClass()):
            continue

        try:
            if not act.isValidContext(context):
                continue
        except:
            # Sometimes this raises an exception - even though it shouldn't
            continue

        if not act.isEnabledForContext(context):
            continue

        symbols.append(action_entry(context, act))

    return symbols


def get_symbols():
    program = getCurrentProgram()
    mod_number = _program_mod_number(program)
    cache_key = None
    if mod_number is not None:
        cache_key = _program_cache_key(program)
        cached = _SYMBOL_CACHE.get(cache_key)
        if cached and cached.get("mod") == mod_number:
            _touch_symbol_cache(cache_key)
            return cached.get("symbols", [])

    symbols = []
    symbolTable = program.getSymbolTable()
    mem = program.getMemory()
    for symbol in symbolTable.getAllSymbols(True):
        if not mem.contains(symbol.getAddress()):
            continue

        if symbol.source == SourceType.DEFAULT:
            if symbol.getName().startswith("LAB_"):
                # Really boring symbols.
                continue

        if symbol.symbolType == SymbolType.FUNCTION:
            symbols.append(function_symbol_entry(symbol))
        else:
            symbols.append(data_symbol_entry(symbol))

    if mod_number is not None and cache_key is not None:
        _SYMBOL_CACHE[cache_key] = {"mod": mod_number, "symbols": symbols}
        _touch_symbol_cache(cache_key)
    return symbols


def get_component_providers():
    symbols = []
    for cp in getState().getTool().getWindowManager().getComponentProviders(Object):
        symbols.append(component_provider_entry(cp))

    return symbols


def get_scripts():
    symbols = []
    for script_dir in GhidraScriptUtil.getScriptSourceDirectories():
        script_files = script_dir.listFiles()        
        for scr_file in script_files:
            symbols.append(script_entry(scr_file))

    return symbols


def get_bookmarks():
    symbols = []
    for mark in getCurrentProgram().getBookmarkManager().getBookmarksIterator():
        symbols.append(bookmark_entry(mark))

    return symbols


WINDOW_NAME = "CtrlP - " + str(getCurrentProgram().getDomainFile())


def run():
    symbols = []
    invoke_later(lambda: SymbolFilterWindow(WINDOW_NAME, symbols).setVisible(True))


def run_or_restore():
    for window in Window.getWindows():
        if isinstance(window, JFrame):
            if window.getTitle() == WINDOW_NAME and window.isDisplayable():
                if not window.isShowing():
                    window.setVisible(True)
                else:
                    print("Window is alredy visible. Doing nothing")
                return
    run()


if __name__ == "__main__":
    run_or_restore()
