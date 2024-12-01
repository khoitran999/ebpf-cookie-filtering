import yaml

def load_config(config_file='config.yaml'):
    with open(config_file, 'r') as f:
        return yaml.safe_load(f)

config = load_config()
