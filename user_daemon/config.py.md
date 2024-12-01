# Internal Code Documentation: Configuration Loading Module

[TOC]

## 1. Overview

This module is responsible for loading configuration settings from a YAML file.  The primary function, `load_config`, reads a YAML file and returns its contents as a Python dictionary.  This dictionary is then assigned to the `config` variable for global access within the application.


## 2. Function Details

### 2.1 `load_config(config_file='config.yaml')`

This function loads configuration data from a YAML file.

| Parameter       | Type      | Description                                          | Default Value |
|-----------------|-----------|------------------------------------------------------|----------------|
| `config_file` | `str`     | Path to the YAML configuration file.                 | `'config.yaml'` |


**Functionality:**

1. **File Opening:** The function attempts to open the specified `config_file` in read mode (`'r'`).  A `FileNotFoundError` exception will be raised if the file does not exist.  It's assumed the file is properly formatted YAML.  Error handling for malformed YAML is not explicitly implemented in this function, relying on `yaml.safe_load`'s inherent error handling.

2. **YAML Parsing:** The `yaml.safe_load(f)` function from the `PyYAML` library parses the YAML data from the opened file object (`f`).  `yaml.safe_load` is used to prevent arbitrary code execution from potentially malicious YAML files.  This function safely loads the YAML into a Python dictionary or list, depending on the YAML structure.

3. **Return Value:** The function returns the parsed YAML data as a Python dictionary (or list, if the YAML file is structured that way).


**Algorithm:**

The algorithm is straightforward:

1. Open the specified YAML file.
2. Parse the YAML content using `yaml.safe_load`.
3. Return the parsed data.


**Example Usage:**

```python
my_config = load_config('my_config.yaml')
print(my_config)  # Prints the loaded configuration data
```


## 3. Global Variable

### 3.1 `config`

This variable stores the configuration data loaded by `load_config()`. It's accessible throughout the application after the `load_config()` function is called.  Its structure mirrors the structure of the YAML configuration file.  Example: if the YAML has `database: {host: localhost}`, then `config['database']['host']` would equal `localhost`.
