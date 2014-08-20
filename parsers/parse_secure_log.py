#!/usr/bin/env python
'''
A script to parse secure logs and an example of how to parse logs that your match start in some line and finish and another
'''

__version__ = '0.0.1'
__author__ = 'Renan Vicente <renanvice@gmail.com>'

import re


class SecureLogParser(object):

        def parse_log(self,filename):

                REGEX_LINE = re.compile(r'(\w{3} \d{2} \w{2}:\w{2}:\w{2}) (\S+) (\w+)\[(\d+)\]: (.*)', re.IGNORECASE)
                REGEX_MESSAGE = re.compile(r'.*\s(\S+)\s\S+\s(\d+.\d+.\d+.\d+).*', re.IGNORECASE)
                
                open_sessions = {}
                logfile = open(filename,'r')
                
                for line in logfile:
                        match = REGEX_LINE.match(line)
                        if match:
                                date     = match.group(1)
                                hostname = match.group(2)
                                service  = match.group(3)
                                session  = match.group(4)
                                message  = match.group(5)
                                if session not in open_sessions and 'Accept' in message:
                                        open_sessions[session] = {}
                                        open_sessions[session]['Start']=date
                                        open_sessions[session]['hostname']=hostname
                                        open_sessions[session]['service']=service
                                        match_message = REGEX_MESSAGE.match(message)
                                        if match_message:
                                                user = match_message.group(1)
                                                ip   = match_message.group(2)
                                                open_sessions[session]['ip'] = ip
                                                open_sessions[session]['user'] = user
                                elif session in open_sessions and 'closed' in message:
                                        open_sessions[session]['End']=date
                
                
                return open_sessions
                
if __name__ == '__main__':
        secure_log = SecureLogParser()
        dictionary_parsed = secure_log.parse_log('secure.log')
        for session in dictionary_parsed:
                parsed = dictionary_parsed[session]
                if 'End' in parsed:
                  print("%s     %s      %s      %s" % (parsed['ip'],parsed['user'],parsed['Start'],parsed['End']))
                else:
                  print("%s     %s      %s      %s" % (parsed['ip'],parsed['user'],parsed['Start'], 'Still logged in'))
