"""The kinds of read a scan run records (req-qualys-subscription-run), in a module that imports nothing.

They live apart from :mod:`tap_plugin.qualys.decompose` so that :mod:`tap_plugin.qualys.live` and the
observation command can name them without importing the grid's models.
"""

COMPLETE = "complete"
WINDOW = "window"
NARROWER = "narrower"
