from configparser import ConfigParser
import os.path


def network_configuration_loader(filename="config.ini"):
    """
        loads the network configuration data
    """
    script_abs = os.path.dirname(__file__)
    conf_dir = os.path.join(script_abs, "../config/config.ini")
    config = ConfigParser()
    config.read(conf_dir)
    # print(os.path.exists('../config/config.ini'))
    net_info_dict = config['net_info']
    localhost = net_info_dict['localhost']
    port = net_info_dict['port']
    return localhost, port
