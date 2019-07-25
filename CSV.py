import csv, os, glob, re

class CSV():

    def __init__(self, file_name="file.csv", folder_name=""):

        self.file_name = file_name
        self.folder_name = folder_name
        self.current_file_name = ""
        self.rows = 0
        self.csv_w = None
        self.csv_r = None
        if(self.file_name.endswith(".csv") is True):
            pass
        else:
            self.file_name = self.file_name + ".csv"

        def create_folder(folder_name):
            if(self.folder_name != ""):
                if (os.path.exists(folder_name)):
                    pass
                else:
                    os.makedirs(folder_name)
            else:
                pass

        create_folder(self.folder_name)

    def create_empty_csv(self):
        file_name = self.file_name.replace(".csv", "")
        numbers = []
        if(self.folder_name == ""):
            pass
        else:
            file_name = self.folder_name + "/" + file_name
        for fn in glob.glob(file_name + "*.csv"):
            val = re.findall('\d+', fn)
            if(len(val) == 0):
                pass
            else:
                numbers.append(int(val[0]))
        if(len(numbers) == 0):
            numbers.append(0)
        new_index = max(numbers) + 1
        file_name = file_name + "_" + str(new_index) + ".csv"
        self.csv_w = open(file_name, "a+")
        self.csv_r = open(file_name, "r")
        if(self.folder_name != ""):
            part_of_name = file_name.split("/")
            self.current_file_name = part_of_name[len(part_of_name)-1]
        else:
            self.current_file_name = file_name

    def add_row(self, row):
        csv_writer = csv.writer(self.csv_w, delimiter=",")
        csv_writer.writerow(row)
        self.rows = self.rows + 1

    def close_csv(self):
        if(self.csv_w is not None):
            self.csv_w.close()
        if(self.csv_r is not None):
            self.csv_r.close()

    def open_csv(self):
        file_name = self.get_file_path()
        try:
            self.csv_w = open(file_name, "a+")
            self.csv_r = open(file_name, "r")
        except Exception as e:
            print(e)
        if(self.csv_r is not None):
            try:
                csv_reader = csv.reader(self.csv_r, delimiter=",")
                self.rows = 0
                for row in csv_reader:
                    self.rows += 1
            except Exception as e:
                print(e)
        else:
            pass

    '''
    def read_row(self, row_number):
        file_name = self.get_file_path()
        if(self.csv_r is not None):
            try:
                csv_reader = csv.reader(self.csv_r, delimiter=",")
                for row in csv_reader:
                    print(row)
            except Exception as e:
                print (e)
    '''


    def get_number_of_rows(self, ignore_header=True):
        if(ignore_header is True):
            return self.rows - 1
        else:
            return self.rows
    '''

    def get_file_name(self):
        return self.file_name
    
    def set_folder_name(self, folder_name):
        self.folder_name = folder_name

    def set_file_name(self, file_name):
        self.file_name = file_name
    '''

    def get_folder_name(self):
        return self.folder_name

    def get_current_file_name(self):
        return self.current_file_name

    def get_file_path(self):
        if(self.get_folder_name() == ""):
            return self.get_current_file_name()
        else:
            return self.get_folder_name() + "/" + self.get_current_file_name()