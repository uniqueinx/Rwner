#!/usr/bin/env python
try:
    import requests
    import re
    import sys
    import os
    import subprocess
    import argparse
    import threading
    import time
    from colorama import Fore, Style, init, deinit
except:
    print'''This tool requires **** & **** to be installed,so please consider installing them if you really wish to use it '''
    sys.exit()

__author__ = 'uniqueix'


# ===================================================
# TODO input ip ranges in a good form ==> ############################################
# TODO check for validation of ips and not null ==> ##################################
# TODO convert every thing to multithreading
# TODO arggemnts oragnizing ==> ######################################################
# TODO hint about increasing timeout for slow connection
# TODO with testing with wordlist 3 or 4 time outs and release it
# TODO report about time out exception ==> ###########################################
# TODO revise all the comments and prints
# TODO make it for users wordlist ==> ################################################
# TODO basic authentication type
# TODO
# ===================================================


# class for changing text colors just for indications
class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'


live_threads = []
dead_threads = []
runningThreadsNum = 0
threads = []
Lock = threading.Lock()
vulnerable = []
liveHosts = []
thread_limit = 64


def loadFile(file):
    openfile = open(file, 'r')
    lst = []
    for line in openfile:
        if line:
            lst.append(line.replace('\n', ''))
    openfile.close()
    return lst


def initArgs():
    # Init Arguments Parser
    parser = argparse.ArgumentParser(description='wheres description')
    parser.add_argument('-t', '--timeout', help='Timeout for probing')
    parser.add_argument('-w', '--wordlist', help='Password wordlist to be used in authentication tries')
    parser.add_argument('-u', '--users', help='Users wordlist to be used in authentication tries')
    parser.add_argument('-ip', '--ip',
                        help='IPs to be tested\n could be one IP ex. 192.168.1.1\n or range of IPs ex. 192.168.1-5.1-10',
                        required=True)
    # parser.add_argument('-t', '--threads', help='Threads number')
    return parser.parse_args()


def tryAuthinticate(host, users, wordlist, time_out):
    returnValue = ()
    for user in users:
        for passwd in wordlist:
            url_base = 'http://%s:%s@%s' % (user, passwd, host)
            try:
                request = requests.get(url_base, timeout=time_out)
                if request.status_code == 200:
                    print '%s[+] %s is vulnerable & accessible.\nUser: %s\tpasswd: %s%s' % (
                        bcolors.OKGREEN, host, user, passwd, bcolors.ENDC)
                    returnValue = (host, user, passwd)
                    return returnValue
                elif request.status_code == 401:
                    print '%s[-] %s Failed to authorise.%s' % (bcolors.FAIL, host, bcolors.ENDC)
            except requests.exceptions.Timeout:
                print 'got timeout exception'
                pass
            except requests.exceptions.ConnectionError:
                print 'got connection error'
                pass
            except:
                print 'Got unknown exception!!!'
                pass
    return


def detecting_live_hosts(ips):
    for ip3 in xrange(ips[0][0], ips[0][1]):
        for ip2 in xrange(ips[1][0], ips[1][1]):
            for ip1 in xrange(ips[2][0], ips[2][1]):
                for ip0 in xrange(ips[3][0], ips[3][1]):
                    host = '%s.%s.%s.%s' % (ip3, ip2, ip1, ip0)
                    if thread_limit == 0:
                        run_isAlive(host)
                    else:
                        while len(live_threads) > thread_limit:
                            print '%s[*] Sleeping for a second :D%s' % (bcolors.OKBLUE, bcolors.ENDC)
                            time.sleep(1)
                    thread_ = threading.Thread(target=run_isAlive, args=(host,))
                    live_threads.append(thread_)
                    thread_.start()
                    del dead_threads[:]
    for t in live_threads:
        t.join()
    print "Exiting Detecting live hosts"


def generateHostlst(ips):
    liveHosts = []
    for ip3 in xrange(ips[0][0], ips[0][1]):
        for ip2 in xrange(ips[1][0], ips[1][1]):
            for ip1 in xrange(ips[2][0], ips[2][1]):
                for ip0 in xrange(ips[3][0], ips[3][1]):
                    host = '%s.%s.%s.%s' % (ip3, ip2, ip1, ip0)
                    liveHosts.append(host)
    return liveHosts


def isAlive(ip):
    return subprocess.call(["ping", ip, "-c 1"], stdout=open(os.devnull, "w"), stderr=subprocess.STDOUT)


class authenticationThread(threading.Thread):
    def __init__(self, threadID, host, user, wordlist, timeout):
        threading.Thread.__init__(self)
        self.threadID = threadID
        self.host = host
        self.user = user
        self.wordlist = wordlist
        self.timeout = timeout

    def run(self):
        result = tryAuthinticate(self.host, self.user, self.wordlist, self.timeout)
        global threads, runningThreadsNum, Lock, vulnerable
        if result:
            Lock.acquire()
            vulnerable.append(result)
            Lock.release()
        # print 'self', self
        # print len(threads)
        # print threads

        threads.remove(self)
        runningThreadsNum -= 1

        # print len(threads)


def run_isAlive(ip):
    try:
        if not isAlive(ip):
            print '%s[+] %s is Alive.%s' % (bcolors.OKGREEN, ip, bcolors.ENDC)
            liveHosts.append(ip)
        else:
            print '%s[-] %s is Dead.%s' % (bcolors.FAIL, ip, bcolors.ENDC)
    except:
        raise
    finally:
        move_to_dead(threading.current_thread())


def move_to_dead(thread):
    dead_threads.append(thread)
    live_threads.remove(thread)
    # print Fore.YELLOW + 'Exiting thread' + threading.current_thread().name, len(live_threads) , len(dead_threads)


def main_thread():
    numOfThreads = 10
    timeOut = 1
    liveHostsfile = 'hosts.txt'
    wordList = ['admin', 'iadmin']
    users = ['admin']
    ipRanges = ''
    lstOfIps = []
    ipRangeRegex = r'([0-9]{1,3})(\-[0-9]{1,3})?\.([0-9]{1,3})(\-[0-9]{1,3})?\.([0-9]{1,3})(\-[0-9]{1,3})?\.([0-9]{1,3})(\-[0-9]{1,3})?'

    args = initArgs()
    if args.timeout:
        timeOut = int(args.timeout)
    if args.wordlist:
        wordList = loadFile(args.wordlist)

    ipRange = args.ip
    ip = re.findall(ipRangeRegex, ipRange)

    if not ip:
        print 'please provide a valid ip address or range\nex. 192.168.1.1 or 192.168.1-10.1-10'
        sys.exit(2)

    ip = ip[0]

    for i in xrange(0, 8, 2):
        tmp = int(ip[i])
        r = [tmp]
        if ip[i + 1]:
            tmp = int(ip[i + 1][1:]) + 1
            r.append(tmp)
        else:
            r.append(tmp + 1)
        lstOfIps.append(r)

    # Detecting live hosts
    detecting_live_hosts(lstOfIps)

    # for testing only
    # liveHosts = generateHostlst(lstOfIps)
    # liveHosts = loadFile('hosts.txt')
    # int liveHosts


    # Trying to authenticate
    global runningThreadsNum, threads, vulnerable
    while liveHosts:
        if runningThreadsNum < numOfThreads:
            # print numOfThreads, runningThreadsNum, len(liveHosts)
            print 'Trying to authenticate ', liveHosts[0]
            x = authenticationThread(runningThreadsNum, liveHosts.pop(0), users, wordList, timeOut)
            runningThreadsNum += 1
            threads.append(x)
            x.start()
            # print 'list', len(liveHosts),'threads', len(threads)
            # print threads
    for thread in threads:
        thread.join()

    while threads:
        pass
    for ip in vulnerable:
        print Fore.GREEN + '[+] %s is accessible with %s, %s' % (ip)


def main():
    init()
    print Style.BRIGHT
    main_thread()
    deinit()

if __name__ == "__main__":
    main()
