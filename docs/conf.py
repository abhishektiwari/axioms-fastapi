"""Sphinx configuration for axioms-fastapi documentation."""

import os
import sys

# Add the project root to sys.path for autodoc
sys.path.insert(0, os.path.abspath(".."))
sys.path.insert(0, os.path.abspath("../src"))

# Project information
project = "axioms-fastapi"
copyright = "2025, Abhishek Tiwari"
author = "Abhishek Tiwari"

# General configuration
extensions = [
    "sphinx.ext.autodoc",
    "sphinx.ext.autosummary",
    "sphinx.ext.napoleon",
    "sphinx.ext.viewcode",
    "sphinx.ext.intersphinx",
    "sphinx.ext.doctest",
    "sphinx_copybutton",
]

# Autodoc settings
autodoc_default_options = {
    "members": True,
    "member-order": "bysource",
    "special-members": "__init__",
    "undoc-members": True,
    "exclude-members": "__weakref__",
}

autosummary_generate = True
autodoc_typehints = "description"

# Napoleon settings (for Google/NumPy style docstrings)
napoleon_google_docstring = True
napoleon_numpy_docstring = False
napoleon_include_init_with_doc = True
napoleon_include_private_with_doc = False
napoleon_include_special_with_doc = True
napoleon_use_admonition_for_examples = True
napoleon_use_admonition_for_notes = True
napoleon_use_admonition_for_references = False
napoleon_use_ivar = False
napoleon_use_param = True
napoleon_use_rtype = True
napoleon_preprocess_types = False
napoleon_type_aliases = None
napoleon_attr_annotations = True

# Syntax highlighting
pygments_style = "sphinx"
highlight_language = "python3"

# Intersphinx mapping
intersphinx_mapping = {
    "python": ("https://docs.python.org/3", None),
    "fastapi": ("https://fastapi.tiangolo.com/", None),
}

# Templates
templates_path = ["_templates"]
exclude_patterns = ["_build", "Thumbs.db", ".DS_Store"]

# HTML output
html_theme = "sphinx_book_theme"
html_static_path = ["_static"]
# Custom CSS files
html_css_files = [
    'custom.css',
]
html_theme_options = {
    "repository_url": "https://github.com/abhishektiwari/axioms-fastapi",
    "repository_provider": "github",
    "repository_branch": "main",
    "path_to_docs": "docs",
    "use_issues_button": True,
    "use_repository_button": True,
    "use_edit_page_button": True,
    "use_download_button": False,
    "use_fullscreen_button": True,
    "use_sidenotes": True,
    "icon_links_label": "Quick Links",
    "icon_links": [
        {
            "name": "GitHub",
            "url": "https://github.com/abhishektiwari/axioms-fastapi",
            "icon": "fa-brands fa-square-github",
            "type": "fontawesome",
        },
        {
            "name": "Abhishek Tiwari",
            "url": "https://www.abhishek-tiwari.com",
            "icon": "https://www.abhishek-tiwari.com/images/logo.svg",
            "type": "local",
        },
        {
            "name": "PyPI",
            "url": "https://pypi.org/project/axioms-fastapi/",
            "icon": "fa-brands fa-python",
            "type": "fontawesome",
        },
   ]
}

# Additional options
add_module_names = False
