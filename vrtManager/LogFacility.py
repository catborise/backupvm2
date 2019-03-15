import logging



class Log(object):
    def __init__(self, log_level="DEBUG", log_filename="backupjob.log", log_file_mode="a"):
        # Logger create
        self.logger = logging.getLogger("BackupLogs")

        # Console log config
        ch = logging.StreamHandler()
        ch.setLevel(getattr(logging, log_level.upper()))
        formatter = logging.Formatter('%(asctime)s-%(levelname)-8s- %(message)s')
        ch.setFormatter(formatter)
        # add console config to logger
        self.logger.addHandler(ch)

        log_file = 'log/' + log_filename + '.log'
        logging.basicConfig(filename=log_file, filemode=log_file_mode, format='[%(asctime)s] %(levelname)-8s - %(message)s', level=getattr(logging, log_level.upper()))

    def getlogger(self):
        return logging.getLogger("BackupLogs")
