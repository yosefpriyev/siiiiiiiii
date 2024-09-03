import requests
import os
from tkinter import *
import time

class scaning:
    def __init__(self, path, apikey):
        self.path = path
        self.apikey = apikey
        self.erorrfiledict = {}
        self.filelist = []
        self.unsafefiles = {}
        self.safefiles = {}

    def send_to_scan(self, apikey: str, path: str):
        url = 'https://www.virustotal.com/vtapi/v2/file/scan'
        file = {'file': open(path, 'rb')}
        par = {'apikey': apikey}

        res = requests.post(url=url,files=file,params=par)
        time.sleep(30)
        if res.status_code != 200:
            return path, f'error code = {res.status_code}', res.json()
        return path, None, res.json()

    def list_files_in_directory(self, root_directory: str):
        filelist1 = []
        for dirpath, dirnames, filenames in os.walk(root_directory):
            for filename in filenames:
                filelist1.append(os.path.join(dirpath, filename))
        if filelist1 != []:
            for item in filelist1:
                self.filelist.append(item.replace('\\\\', '\\'))
        return self.filelist

    def printresult(self):
        safe = {}
        unsafe = {}
        for item in self.safefiles:
            status = self.safefiles[item]
            name = os.path.basename(item)
            if status == 'clean':
                safe[name] = status
            else:
                unsafe[name] = status
        if safe != {}:
            print('safe files!')
            for item in safe:
                print(f'{item}: {safe[item]}')
        if unsafe != {}:
            print('unsafe files!')
            for item in unsafe:
                print(f'{item}: {unsafe[item]}')
            
    def scan(self):
        path = pathen.get()
        list1 = self.list_files_in_directory(path)
        for item in list1:
            errorpath, error, jsonfile = self.send_to_scan(self.apikey,item)
            if error != None:
                self.erorrfiledict[errorpath] = error
            else:
                scanid = jsonfile.get('scan_id')
                if scanid:
                    self.safefiles[item] = 'clear'
                else:
                    self.unsafefiles[item] = jsonfile
        self.printresult()
        window.destroy()

def execute():
    scanv = scaning(path=pathen.get(), apikey='your virus total API key!')
    scanv.scan()

window = Tk()
window.title('GUI virus total API file scanner by YOSEF PRIYEV')
head = Label(window, 
            text='welcome to my scanner',
            bg='black',
            fg='#00FF00',
            font=('Ariel',30,'bold'),
            padx=5,
            pady=5,)
head.pack()
pathen = Entry(window, font=('Ariel', 15, 'bold'))
pathen.pack()
startscanning = Button(text='start scan', command=execute)
startscanning.pack()
window.mainloop()
