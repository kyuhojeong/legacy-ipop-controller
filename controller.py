#!/usr/bin/env python

import argparse
import binascii
import code
import ipoplib as i
import observer
import os
import json
import readline
import signal
import sys
import threading
import time
import groupvpn as vpn

CONFIG = i.CONFIG

# thread signal
run_event = threading.Event()

def exit_handler(signum, frame):
    print "SIGINT captured"
    run_event.clear()

def setup_config(config):
    """Validate config and set default value here. Return ``True`` if config is
    changed.
    """
    if not config["local_uid"]:
        uid = binascii.b2a_hex(os.urandom(CONFIG["uid_size"] / 2))
        config["local_uid"] = uid
        return True # modified
    return False

class IpopController(observer.Observer):
    def __init__(self, argv, logger):

        super(IpopController, self).__init__("controller")
        self.observable = observer.Observable()
        self.observable.register(self)

        self.logging = logger
        logger.info("say something i'm ipop")

        # Parsing stdin arguments
        parser = argparse.ArgumentParser()
        parser.add_argument("-c", help="load configuration from a file",
                        dest="config_file", metavar="config_file")
        parser.add_argument("-u", help="update configuration file if needed",
                        dest="update_config", action="store_true")
        parser.add_argument("-p", help="load remote ip configuration file",
                        dest="ip_config", metavar="ip_config")
        parser.add_argument("-s", help="configuration as json string (overrides "
                        "configuration from file)", dest="config_string", 
                        metavar="config_string")
        parser.add_argument("--pwdstdout", help="use stdout as password stream",
                        dest="pwdstdout", action="store_true")
        parser.add_argument("-i", help="Interactive mode",
                        dest="interactive", action="store_true")
        parser.add_argument("--child_thread", action="store_true",
                            dest="child_thread", help="This is for integrating"
                                         "ipop controller with RYU framework")

        self.args = parser.parse_args(argv)

        # Take configuration file
        if self.args.config_file:
            # Load the config file
            with open(self.args.config_file) as f:
                loaded_config = json.load(f)
            CONFIG.update(loaded_config)
    
        if self.args.config_string:
            # Load the config string
            loaded_config = json.loads(args.config_string)
            CONFIG.update(loaded_config)
    
        need_save = setup_config(CONFIG)
        if need_save and self.args.config_file and self.args.update_config:
            with open(self.args.config_file, "w") as f:
                json.dump(CONFIG, f, indent=4, sort_keys=True)
    
        if not ("xmpp_username" in CONFIG and "xmpp_host" in CONFIG):
            raise ValueError("At least 'xmpp_username' and 'xmpp_host' must be "
                             "specified in config file or string")
    
        if "xmpp_password" not in CONFIG:
            prompt = "\nPassword for %s: " % CONFIG["xmpp_username"]
            if self.args.pwdstdout:
              CONFIG["xmpp_password"] = getpass.getpass(prompt, stream=sys.stdout)
            else:
              CONFIG["xmpp_password"] = getpass.getpass(prompt)
        
        if "controller_logging" in CONFIG:
            try:
                level = getattr(logger, CONFIG["controller_logging"])
                logger.getLogger().setLevel(level)
            except:
                # This is for RYU logger. It does not use convernional logger
                # level such as INFO, DEBUG, ERROR. Rather, it uses lowerletter
                # such as info, debug and error.
                level = getattr(logger, CONFIG["controller_logging"].lower())
                print dir(logger)
                logger.setLevel(10)
    
        if self.args.ip_config:
            load_peer_ip_config(self.args.ip_config)

    
    def run(self):
        # Start controller thread
        #if CONFIG["controller_type"] == "group_vpn":
        #    import groupvpn as vpn
        #elif CONFIG["controller_type"] == "social_vpn":
        #    import socialvpn as vpn
    
        run_event.set()
        controller = vpn.Controller(CONFIG, self.logging, self.observable, run_event)
        t = controller.run()
    
        # This is not to fall off the main thread
        #if not self.args.child_thread:
        #    while run_event.is_set():
        #        time.sleep(1)

    def on_message(self, msg_type, msg):
        print("on_message type:{0} message:{1}".format(msg_type, msg))


    
if __name__ == "__main__":
    import logging
    signal.signal(signal.SIGINT, exit_handler)
    IpopController(sys.argv[1:], logging).run()

