#author: Peter Okma
import xml.etree.ElementTree as et
import logging

class Feedback():
    """Feeback used by Alfred Script Filter

    Usage:
        fb = Feedback()
        fb.add_item('Hello', 'World')
        fb.add_item('Foo', 'Bar')
        print fb

    """

    def __init__(self):
        self.feedback = et.Element('items')
        self._logger = None

    def __repr__(self):
        """XML representation used by Alfred

        Returns:
            XML string
        """
        return et.tostring(self.feedback)

    def add_item(self, title, subtitle="", arg="", valid="yes", autocomplete="", icon="icon.png"):
        """
        Add item to alfred Feedback

        Args:
            title(str): the title displayed by Alfred
        Keyword Args:
            subtitle(str):    the subtitle displayed by Alfred
            arg(str):         the value returned by alfred when item is selected
            valid(str):       whether or not the entry can be selected in Alfred to trigger an action
            autcomplete(str): the text to be inserted if an invalid item is selected. This is only used if 'valid' is 'no'
            icon(str):        filename of icon that Alfred will display
        """
        item = et.SubElement(self.feedback, 'item', uid=str(len(self.feedback)),
            arg=arg, valid=valid, autocomplete=autocomplete)
        _title = et.SubElement(item, 'title')
        _title.text = title
        _sub = et.SubElement(item, 'subtitle')
        _sub.text = subtitle
        _icon = et.SubElement(item, 'icon')
        _icon.text = icon

    @property
    def logger(self):
        """Create and return a logger that logs to both console and
        a log file.

        Use :meth:`open_log` to open the log file in Console.

        :returns: an initialised :class:`~logging.Logger`

        """

        if self._logger:
            return self._logger

        # Initialise new logger and optionally handlers
        logger = logging.getLogger('workflow')

        if not len(logger.handlers):  # Only add one set of handlers
            console = logging.StreamHandler()

            fmt = logging.Formatter(
                '%(asctime)s %(filename)s:%(lineno)s'
                ' %(levelname)-8s %(message)s',
                datefmt='%H:%M:%S')

            console.setFormatter(fmt)
            logger.addHandler(console)

        logger.setLevel(logging.DEBUG)
        self._logger = logger

        return self._logger