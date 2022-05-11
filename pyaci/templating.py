# Copyright (c) 2014, 2015 Cisco Systems, Inc. All rights reserved.

"""
pyaci.templating
~~~~~~~~~~~~~~~~~~~

This module contains helpers to use Jinja2 templates with PyACI.
"""

import os

import jinja2
import yaml

from .errors import ResourceError


def merge_dict(master, other):
    """Merge the given two dictionaries recursively and return the
    result."""
    if isinstance(master, dict) and isinstance(other, dict):
        for key, value in other.items():
            if isinstance(value, dict):
                if key not in master:
                    master[key] = value
                else:
                    master[key] = merge_dict(master[key], value)
            else:
                master[key] = value
    return master


class TemplateRepository:
    """A Jinja2 template repository.

    :param path: path to a directory containing Jinja2 templates.

    Usage::

      >>> import pyaci
      >>> repo = pyaci.template_repository('path/to/repo')
      >>> xml1 = repo.render('template1.xml', template_values={'count': 2})
      >>> xml2 = repo.render('template2.xml',
                              template_values_file='values2.yml')
      >>> json1 = repo.render('template1.json',
                               template_values_file='values1.yml',
                               template_values={'name': 'bar'})

    """

    def __init__(self, path):
        if not os.path.isdir(path):
            raise ResourceError(f'Path is not valid: {path}')
        self._path = path
        self._jinja2_env = jinja2.Environment(loader=jinja2.FileSystemLoader(self._path))

    def render(self, template_path, template_values_file=None, template_values={}):
        """Render a given template.

        Template values can be specified using a YAML file, or a
        Python dictionary, or both. When both are specifed, the values
        are merged, and the value specified in the dictionary takes
        precedence if there is a conflict.

        :param template_path: path to the template within the repository.
        :param template_values_file: path to the template values YAML file.
        :param template_values: template values dictinary.

        """
        if template_values_file is not None:
            values = yaml.load(self._jinja2_env.get_template(template_values_file).render())
        else:
            values = {}

        values = merge_dict(values, template_values)

        return self._jinja2_env.get_template(template_path).render(values)
