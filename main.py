#!/usr/bin/env python

import logging
import logging.config

from pycoshark.utils import get_base_argparser
from linkSHARK.linkshark import LinkSHARK
from linkSHARK.config import Config, setup_logging

def start():
    setup_logging()
    logger = logging.getLogger("main")
    logger.info("Starting memeSHARK...")

    parser = get_base_argparser('Analyze the given URI. An URI should be a GIT Repository address.', '1.0.0')
    parser.add_argument('-n', '--project-name', help='Name of the project.', required=True)
    parser.add_argument('-ll', '--log_level', help='Log Level for stdout INFO or DEBUG.', required=False, default='INFO')

    args = parser.parse_args()
    cfg = Config(args)

    logger.debug("Got the following config: %s" % cfg)
    link_shark = LinkSHARK()
    link_shark.start(cfg)

if __name__ == "__main__":
    start()