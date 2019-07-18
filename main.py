import os
import sys
from PyQt5 import QtCore, QtWidgets, Qt
from PyQt5.QtWidgets import *
from PyQt5.QtGui import *
from gurobipy import *

from MILP_generator_class import *
from warning_error_class import *



class ARXCryptanalyserWindow(QMainWindow):
    def __init__(self, parent=None):
        super(ARXCryptanalyserWindow, self).__init__(parent)

        self.block_cipher = ['']#the main list for inserting block cipher on it

        #the amount of round and kind of cryptanalisys is put in this list
        self.round_kind_amount = ['1', '']
        
        #create lists for for inserting lineEdits data in them 
        self.branches_indices = []
        self.input_output_indices = []
        self.permutations = []
        self.new_operations = []

        #the icon(symbole) and descreption of each operation (or rotation) are inserted in these list by combo_boxes
        self.icon_operation = ['', '']
        self.icon_rotation = ['', '']
        self.icon_permutation = ['', '']
        self.kind_Sbox = ['', '']

         
        
        #constructing the main layout
        self.setWindowTitle("MILP tool for cryptanalysis of bit-oriented block ciphers")
        #self.setGeometry(250,70, 800, 625)
        self.setFixedSize(800, 625)
        
        

        #=====constructing Menue_bar and inserting save and load option on it=============
        new_file = QAction("New", self)
        new_file.setShortcut('ctrl+n')
        new_file.triggered.connect(self.newFile)
        
        save_file = QAction("Save", self)
        save_file.setShortcut('ctrl+s')
        save_file.triggered.connect(self.saveFile)
        
        load_file = QAction("Load", self)
        load_file.setShortcut('ctrl+l')
        load_file.triggered.connect(self.loadFile)

        quit_file = QAction("Quit", self)
        quit_file.setShortcut('ctrl+q')
        quit_file.triggered.connect(self.quitFile)

        menubar = self.menuBar()
        file = menubar.addMenu('&File')
        file.addAction(new_file)
        file.addAction(save_file)
        file.addAction(load_file)
        file.addAction(quit_file)
        #=====end of constructing Menue_bar and inserting save and load option on it=====
        
        
        #creating the spin button for number of rounds:
        group_box_spin_box = QGroupBox(self)
        group_box_spin_box.setGeometry(25,25,200,70)
        
        title_spin_box = QLabel('number of rounds', self)
        title_spin_box.move(77,20)
        
        self.spin_box = QSpinBox(self)
        self.spin_box.setMinimum(1)
        self.spin_box.setMaximum(1000000)
        self.spin_box.setGeometry(30,70, 190, 20)
        self.spin_box.valueChanged.connect(lambda: self.insert_spin_radio_in_block_cipher('round_amount'))


        #creating the radio button for kind of cryptanalysis
        group_box_kind = QGroupBox(self)
        group_box_kind.setGeometry(575,25,200,70)

        title_kind = QLabel('kind of cryotanalysis', self)
        title_kind.move(630,20)
        
        self.r1 = QRadioButton('differential', self)
        self.r1.setGeometry(595,70, 190, 20)
        self.r1.toggled.connect(lambda: self.insert_spin_radio_in_block_cipher('differential'))

        self.r2 = QRadioButton('linear', self)
        self.r2.setGeometry(705,70, 190, 20)
        self.r2.toggled.connect(lambda: self.insert_spin_radio_in_block_cipher('linear'))
        


        #===================================creating insert new branch window===================================================
        group_box_insert_new_branch = QGroupBox(self)
        group_box_insert_new_branch.setGeometry(15,105,250,130)

        title_insert_new_branch = QLabel('create branch', self)
        title_insert_new_branch.move(100,103)

        self.branch_indice = QLineEdit(self)
        self.branch_indice.setGeometry(70,143,30,30)
        self.branch_indice.setValidator(QIntValidator())
        self.branch_indice.setAlignment(QtCore.Qt.AlignCenter)
        title_branch_indice = QLabel('indice of branch', self)
        title_branch_indice.move(50,118)

        self.branch_size = QLineEdit(self)
        self.branch_size.setGeometry(150,143,30,30)
        self.branch_size.setValidator(QIntValidator())
        self.branch_size.setAlignment(QtCore.Qt.AlignCenter)
        title_branch_size = QLabel('size(bits)', self)
        title_branch_size.move(145,118)

        insert_1 =QPushButton('insert', self)
        insert_1.setGeometry(220,143, 40, 30)
        insert_1.clicked.connect(lambda: self.insert_data_in_list_and_widgetList('insert_new_branch'))

        self.widget_list_new_branch = QListWidget(self)
        self.widget_list_new_branch.setGeometry(20,175,240,55)
        self.widget_list_new_branch.itemDoubleClicked.connect(lambda: self.delete_widget_list_doubleClicked('new_branch_list'))
        #===================================end of creating insert new branch window================================================

        #==================================creating coresponded input output branch window==========================================
        group_box_coresponded_input_output_branch = QGroupBox(self)
        group_box_coresponded_input_output_branch.setGeometry(275,105,250,130)

        title_coresponded_input_output_branch = QLabel('mutual indices', self)
        title_coresponded_input_output_branch.move(370,103)

        self.input_branch = QLineEdit(self)
        self.input_branch.setGeometry(330,143,30,30)
        self.input_branch.setValidator(QIntValidator())
        self.input_branch.setAlignment(QtCore.Qt.AlignCenter)
        title_input_branch = QLabel('input branch', self)
        title_input_branch.move(315,118)

        self.output_branch = QLineEdit(self)
        self.output_branch.setGeometry(410,143,30,30)
        self.output_branch.setValidator(QIntValidator())
        self.output_branch.setAlignment(QtCore.Qt.AlignCenter)
        title_output_branch = QLabel('output branch', self)
        title_output_branch.move(390,118)

        insert_2 =QPushButton('insert', self)
        insert_2.setGeometry(480,143, 40, 30)
        insert_2.clicked.connect(lambda: self.insert_data_in_list_and_widgetList('insert_input_output'))

        self.widget_list_input_output = QListWidget(self)
        self.widget_list_input_output.setGeometry(280,175,240,55)
        self.widget_list_input_output.itemDoubleClicked.connect(lambda: self.delete_widget_list_doubleClicked('input_output_list'))
        #==================================end of creating coresponded input output branch window=====================================

        #==================================creating P-box window======================================================================
        group_box_coresponded_input_output_branch = QGroupBox(self)
        group_box_coresponded_input_output_branch.setGeometry(535,105,250,130)

        title_coresponded_input_output_branch = QLabel('create P-box', self)
        title_coresponded_input_output_branch.move(640,103)

        self.permut_num = 1
        self.permutation_tag = QLabel('P'+str(self.permut_num), self)
        self.permutation_tag.move(540,143)
        
        self.permutation = QTextEdit(self)
        self.permutation.setGeometry(555,143,170,30)
        self.permutation.setAlignment(QtCore.Qt.AlignCenter)
        self.permutation.sizeHint()
        title_permutation = QLabel('permutation', self)
        title_permutation.move(610,118)

        insert_3 = QPushButton('insert', self)
        insert_3.setGeometry(740,143, 40, 30)
        insert_3.clicked.connect(lambda: self.insert_data_in_list_and_widgetList('insert_permute'))

        self.widget_list_permutation = QListWidget(self)
        self.widget_list_permutation.setGeometry(540,175,240,55)
        #self.widget_list_permutation.itemDoubleClicked.connect(lambda: self.delete_widget_list_doubleClicked('insert_permute'))
        #==================================end of creating S-box and P-box window======================================================

        #==================================creating operation window==================================================================
        group_box_operation = QGroupBox(self)
        group_box_operation.setGeometry(15,245,770,280)

        title_operation = QLabel('describe block-cipher', self)
        title_operation.move(340,243)


        self.cb_1 = QComboBox(self)
        self.cb_1.setGeometry(30,290,43,30)
        title_cb_1 = QLabel('operation', self)
        title_cb_1.move(30,258)
        self.xor_icon = QIcon('xor.png')
        self.cb_1.addItem(self.xor_icon, '')
        self.threeFork_icon = QIcon('threeFork.png')
        self.cb_1.addItem(self.threeFork_icon, ' ')
        self.modularAdd_icon = QIcon('modularAdd.png')
        self.cb_1.addItem(self.modularAdd_icon, '  ')
        self.and_icon = QIcon('and.png')
        self.cb_1.addItem(self.and_icon, '   ')
        self.cb_1.activated.connect(lambda: self.insert_comboBoxes_detatils_in_listWidget('operation'))
        
        self.input1_indice = QLineEdit(self)
        self.input1_indice.setGeometry(100,290,30,30)
        self.input1_indice.setValidator(QIntValidator())
        self.input1_indice.setAlignment(QtCore.Qt.AlignCenter)
        title_input1_indice = QLabel('1st input', self)
        title_input1_indice.move(95,258)

        self.input2_indice = QLineEdit(self)
        self.input2_indice.setGeometry(160,290,30,30)
        self.input2_indice.setValidator(QIntValidator())
        self.input2_indice.setAlignment(QtCore.Qt.AlignCenter)
        title_input2_indice = QLabel('2nd input', self)
        title_input2_indice.move(150,258)

        self.output_indice = QLineEdit(self)
        self.output_indice.setGeometry(220,290,30,30)
        self.output_indice.setValidator(QIntValidator())
        self.output_indice.setAlignment(QtCore.Qt.AlignCenter)
        title_output_indice = QLabel('output', self)
        title_output_indice.move(220,258)

        self.insert_4 =QPushButton('insert', self)
        self.insert_4.setGeometry(280,290, 40, 30)
        self.insert_4.clicked.connect(lambda: self.insert_data_in_list_and_widgetList('insert_operation_details'))


        self.cb_2 = QComboBox(self)
        self.cb_2.setGeometry(30,355,43,30)
        title_cb_2 = QLabel('transfer', self)
        title_cb_2.move(30,323)
        self.rotl_icon = QIcon('rotl.png')
        self.cb_2.addItem(self.rotl_icon, '')
        self.rotr_icon = QIcon('rotr.png')
        self.cb_2.addItem(self.rotr_icon, ' ')
        self.cb_2.activated.connect(lambda: self.insert_comboBoxes_detatils_in_listWidget('rotation'))

        self.amount_rotate = QLineEdit(self)
        self.amount_rotate.setGeometry(100,355,30,30)
        self.amount_rotate.setValidator(QIntValidator())
        self.amount_rotate.setAlignment(QtCore.Qt.AlignCenter)
        title_amount_rotate = QLabel('amount', self)
        title_amount_rotate.move(100,323)

        self.rotated_branch_indice = QLineEdit(self)
        self.rotated_branch_indice.setGeometry(160,355,30,30)
        self.rotated_branch_indice.setValidator(QIntValidator())
        self.rotated_branch_indice.setAlignment(QtCore.Qt.AlignCenter)
        title_branch_indice = QLabel('indice', self)
        title_branch_indice.move(165,323)

        self.insert_5 =QPushButton('insert', self)
        self.insert_5.setGeometry(220,355, 40, 30)
        self.insert_5.clicked.connect(lambda: self.insert_data_in_list_and_widgetList('insert_rotation_details'))

        
        self.cb_3 = QComboBox(self)
        self.cb_3.setGeometry(30,420,43,30)
        title_cb_3 = QLabel('S-box', self)
        title_cb_3.move(35,388)
        #self.and_icon = QIcon('and.png')
        #self.cb_3.addItem(self.and_icon, '')
        #self.cb_3.activated.connect(lambda: self.insert_comboBoxes_detatils_in_listWidget('kind_Sbox'))
       
        self.size_Sbox = QLineEdit(self)
        self.size_Sbox.setGeometry(100,420,30,30)
        self.size_Sbox.setValidator(QIntValidator())
        self.size_Sbox.setAlignment(QtCore.Qt.AlignCenter)
        title_size_Sbox = QLabel('size', self)
        title_size_Sbox.move(105, 388)
               
        self.input_Sbox = QLineEdit(self)
        self.input_Sbox.setGeometry(160,420,30,30)
        self.input_Sbox.setValidator(QIntValidator())
        self.input_Sbox.setAlignment(QtCore.Qt.AlignCenter)
        title_input_Sbox = QLabel('input', self)
        title_input_Sbox.move(165,388)

        self.output_Sbox = QLineEdit(self)
        self.output_Sbox.setGeometry(220,420,30,30)
        self.output_Sbox.setValidator(QIntValidator())
        self.output_Sbox.setAlignment(QtCore.Qt.AlignCenter)
        title_output_Sbox = QLabel('output', self)
        title_output_Sbox.move(220,388)

        self.insert_6 =QPushButton('insert', self)
        self.insert_6.setGeometry(280,420, 40, 30)
        self.insert_6.clicked.connect(lambda: self.insert_data_in_list_and_widgetList('insert_substitution_details'))


        self.cb_4 = QComboBox(self)
        self.cb_4.setGeometry(30,485,43,30)
        title_cb_4 = QLabel('P-box', self)
        title_cb_4.move(35,453)

        self.branch_indice_Pbox = QLineEdit(self)
        self.branch_indice_Pbox.setGeometry(100,485,30,30)
        self.branch_indice_Pbox.setValidator(QIntValidator())
        self.branch_indice_Pbox.setAlignment(QtCore.Qt.AlignCenter)
        title_branch_indice_Pbox = QLabel('indice', self)
        title_branch_indice_Pbox.move(100,453)

        self.insert_7 =QPushButton('insert', self)
        self.insert_7.setGeometry(160,485, 40, 30)
        self.insert_7.clicked.connect(lambda: self.insert_data_in_list_and_widgetList('insert_permutation_details'))
        

        self.widget_list_new_operation = QListWidget(self)
        self.widget_list_new_operation.setGeometry(570,290,210,225)
        self.widget_list_new_operation.itemDoubleClicked.connect(lambda: self.delete_widget_list_doubleClicked('new_operation_list'))
        title_branch_indice = QLabel('statements', self)
        title_branch_indice.move(650, 258)
        #==================================end of creating operation window==============================================================

        #==================================creating the execude window===================================================================
        group_box_execude_window = QGroupBox(self)
        group_box_execude_window.setGeometry(15,535,770,80)

        title_execude_window = QLabel('execution', self)
        title_execude_window.move(380,529)
                
        self.t1 =QPushButton('construct model in Gurobi format', self)
        self.t1.setGeometry(30,555, 190, 25)
        self.t1.clicked.connect(lambda: self.execude_window_pushButtons('gurobi_equations'))
        
        self.t2 =QPushButton('construct model in CPLEX format', self)
        self.t2.setGeometry(30,585, 190, 25)
        self.t2.clicked.connect(lambda: self.execude_window_pushButtons('Cplex_equations'))
        
        self.t3 =QPushButton('analyze with Gurobi', self)
        self.t3.setGeometry(305,555, 190, 25)
        #t3.setGeometry(305,565, 190, 25)
        self.t3.clicked.connect(lambda: self.execude_window_pushButtons('analyze_model'))
        
        self.t4 =QPushButton('characteristic of variables ', self)
        self.t4.setGeometry(305,585, 190, 25)
        self.t4.setEnabled(False)
        self.t4.clicked.connect(lambda: self.execude_window_pushButtons('variables_char'))
        
        self.t5 =QPushButton('search impossible input and output', self)
        self.t5.setGeometry(580,555, 190, 25)
        self.t5.clicked.connect(lambda: self.execude_window_pushButtons('impossible_trails'))
        
        self.t6 = QPushButton('report', self)
        self.t6.setGeometry(580,585, 190, 25)
        self.t6.clicked.connect(lambda: self.execude_window_pushButtons('log_equations'))
        #==================================end of creating the execude window===================================================================

   
    #inserting data from drived lists in to self.block_cipher list
    def organize_block_cipher(self):

        self.block_cipher.append(list(self.round_kind_amount))
        del self.block_cipher[0]
        
        branches_indices_size = len(self.branches_indices)
        input_output_size = len(self.input_output_indices)
        new_operations_size = len(self.new_operations)

        input_output_indices = ['']
        for i in range(input_output_size):
            input_output_indices.append(list(self.input_output_indices[i]))
        del input_output_indices[0]

        new_operations = ['']
        for i in range(new_operations_size):
            new_operations.append(list(self.new_operations[i]))
        del new_operations[0]

        


        #inserting the size of each branch in corresponded_input_output list alongside
        for i in range(input_output_size):
            for j in range(branches_indices_size):
                
                if input_output_indices[i][0] == self.branches_indices[j][0]:
                   input_output_indices[i].append(input_output_indices[i][1])
                   input_output_indices[i].append(self.branches_indices[j][1])
                   input_output_indices[i][1] = self.branches_indices[j][1]
                   break
                

        #inserting the size of each branch in new_operation list alongside
        for i in range(new_operations_size):
            for j in range(branches_indices_size):

                
                if new_operations[i][0] == 'rotl' or new_operations[i][0] == 'rotr':
                    if new_operations[i][2] == self.branches_indices[j][0]:
                        new_operations[i].append(self.branches_indices[j][1])
                        break

                elif new_operations[i][0] == 'xor' or new_operations[i][0] == 'threeFork' or new_operations[i][0] == 'modularAdd' or new_operations[i][0] == 'and':
                    if new_operations[i][1] == self.branches_indices[j][0]:
                        new_operations[i].append(self.branches_indices[j][1])
                        new_operations[i].append(self.new_operations[i][3])
                        new_operations[i].append(self.branches_indices[j][1])
                        new_operations[i][3] = self.new_operations[i][2]
                        new_operations[i][2] = self.branches_indices[j][1]
                        break

                elif new_operations[i][0] == 'S':
                    if new_operations[i][2] == self.branches_indices[j][0]:
                        new_operations[i].append(self.new_operations[i][3])
                        new_operations[i].append(self.branches_indices[j][1])
                        new_operations[i][3] = self.branches_indices[j][1]
                        break

                elif new_operations[i][0] == 'P':
                    if new_operations[i][2] == self.branches_indices[j][0]:
                        new_operations[i].append(self.branches_indices[j][1])
                        break
        
        
        #inserting the obtained results in "self.block_copher" list
        self.block_cipher.append([''])#it's left blncked for inserting the data related to input later
        for i in range(new_operations_size):
            self.block_cipher.append(new_operations[i])
        self.block_cipher.append([''])#it's left blncked for inserting the data related to output later
        
        for i in range(input_output_size):
            self.block_cipher[1].append(input_output_indices[i][0])
            self.block_cipher[1].append(input_output_indices[i][1])

            self.block_cipher[new_operations_size + 2].append(input_output_indices[i][2])
            self.block_cipher[new_operations_size + 2].append(input_output_indices[i][3]) 

        del(self.block_cipher[1][0])
        del(self.block_cipher[new_operations_size + 2][0])



#===============slot function related to menubar==========================================
    #this function save the all data in a file
    def newFile(self):
        
        self.spin_box.setValue(1)
        
        self.r1.setAutoExclusive(False)
        self.r1.setChecked(False)
        self.r1.setAutoExclusive(True)
                
        self.r2.setAutoExclusive(False)
        self.r2.setChecked(False)
        self.r2.setAutoExclusive(True)

        #deleting the all lists 
        self.branches_indices = []
        self.input_output_indices = []
        self.permutations = []
        self.new_operations = []

        #deleting the widget_lists
        self.widget_list_new_branch.clear()
        self.branch_size.clear()
        self.widget_list_input_output.clear()
        self.widget_list_permutation.clear()
        self.widget_list_new_operation.clear()

        self.permut_num = 1
        self.permutation_tag.setText('P1')
        self.cb_4.clear()

        
    #this function save the all data in a file
    def saveFile(self):
        
        #importing data in self.save_load_list 
        save_list = []
        save_list.append(self.round_kind_amount)
        save_list.append(self.branches_indices)
        save_list.append(self.input_output_indices)
        save_list.append(self.permutations)
        save_list.append(self.new_operations)
        
        save_file = QFileDialog.getSaveFileName(self, "Save file", "./", "All files(*)")
        
        if save_file != "":
            with open(save_file[0], "w") as save_data:
                save_data.write(repr(save_list))
                


    #this function load the all data and inserts them in the window
    def loadFile(self):
        #reading the data
        load_file, _ = QFileDialog.getOpenFileName(self, "Open file", "./", "All files(*)", options=QFileDialog.DontUseNativeDialog)

        if load_file:
            
            with open(load_file, "r") as load_data:
                load_list = eval(load_data.read())

            #deleting the widget_lists
            self.widget_list_new_branch.clear()
            self.widget_list_input_output.clear()
            self.widget_list_permutation.clear()
            self.widget_list_new_operation.clear()

            self.cb_4.clear()

            #allocating the data to realted list
            self.round_kind_amount = load_list[0]
            self.branches_indices = load_list[1]
            self.input_output_indices = load_list[2]
            self.permutations = load_list[3]
            self.new_operations = load_list[4]



            #importing data in self.spin_box and (self.r1 or self.r2)
            self.spin_box.setValue(int(self.round_kind_amount[0]))

            if self.round_kind_amount[1] == 'differential':
                self.r1.setChecked(True)
            elif self.round_kind_amount[1] == 'linear':
                self.r2.setChecked(True)
            elif self.round_kind_amount[1] == '':

                self.r1.setAutoExclusive(False)
                self.r1.setChecked(False)
                self.r1.setAutoExclusive(True)
                
                self.r2.setAutoExclusive(False)
                self.r2.setChecked(False)
                self.r2.setAutoExclusive(True)
                
                self.round_kind_amount[1] = ''
                
           

            #importing data in self.widget_list_new_branch
            for i in range(len(self.branches_indices)):
                self.widget_list_new_branch.addItem('                   '+ self.branches_indices[i][0]+
                    '                        '+self.branches_indices[i][1])
            #deleting line edit data in order to put the next data
            self.branch_indice.clear()
            if self.branches_indices:
                self.branch_size.setText(self.branches_indices[-1][1])


            #importing data in self.widget_list_input_output
            for i in range(len(self.input_output_indices)):
                self.widget_list_input_output.addItem('                   '+ self.input_output_indices[i][0]+
                    '                        '+self.input_output_indices[i][1])
            #deleting line edit data in order to put the next data
            self.input_branch.clear()
            self.output_branch.clear()


            #importing data in self.widget_list_permutation
            self.permut_num = len(self.permutations)
            for i in range(len(self.permutations)):
                
                input_permutation = str(0)
                for j in range(len(self.permutations[i])-1):
                    input_permutation += (', '+str(j+1))

                output_permutation = self.permutations[i][0]
                for j in range(len(self.permutations[i])-1):
                    output_permutation += (', '+self.permutations[i][j+1])
                    
                self.widget_list_permutation.addItem( 'P'+str(i+1)+' ('+ input_permutation+') = ('
                    + output_permutation +')' )

            #adding the permutations to the combobox (self.cb_4)
            for i in range(self.permut_num):
                self.cb_4.addItem('P'+str(i+1))
            self.cb_4.activated.connect(lambda: self.insert_comboBoxes_detatils_in_listWidget('permutation'))
                                
            #deleting text edit data in order to put the next data
            self.permutation.clear()

            #preparing the indice of next permutation
            self.permut_num +=1
            self.permutation_tag.setText('P'+ str(self.permut_num))


            #importing data in self.widget_list_new_operationt
            for i in range(len(self.new_operations)):

                #determining Icon for operations and rotations
                if (self.new_operations[i][0] == 'xor'):
                    icon_operation = self.xor_icon
                elif (self.new_operations[i][0] == 'threeFork'):
                    icon_operation = self.threeFork_icon
                elif (self.new_operations[i][0] == 'modularAdd'):
                    icon_operation = self.modularAdd_icon
                elif (self.new_operations[i][0] == 'rotl'):
                    icon_operation = self.rotl_icon
                elif (self.new_operations[i][0] == 'rotr'):
                    icon_operation = self.rotr_icon
                elif (self.new_operations[i][0] == 'and'):
                    icon_operation = self.and_icon

                if (self.new_operations[i][0] == 'rotl' or self.new_operations[i][0] == 'rotr'):
                    item = QListWidgetItem('            ( '+ self.new_operations[i][1]+' )'+
                        '        '+ self.new_operations[i][2])

                    item.setIcon(icon_operation)
                    self.widget_list_new_operation.addItem(item)    

                    #deleting line edits data in order to put the next data
                    self.amount_rotate.clear()
                    self.rotated_branch_indice.clear()


                elif( self.new_operations[i][0] == 'xor' or self.new_operations[i][0] == 'threeFork' or self.new_operations[i][0] == 'modularAdd' or self.new_operations[i][0] == 'and'):       
                    item = QListWidgetItem('              '+ self.new_operations[i][1]+
                        '          '+ self.new_operations[i][2]+'          '+ self.new_operations[i][3])
            
                    item.setIcon(icon_operation)
                    self.widget_list_new_operation.addItem(item)

                    #deleting line edits data in order to put the next data
                    self.input1_indice.clear()
                    self.input2_indice.clear()
                    self.output_indice.clear()

                elif ( self.new_operations[i][0] == 'S' ):
            
            #if self.kind_Sbox[1] == '': #the Sbox is public (not and...)
               # item = QListWidgetItem('S ('+new_substitution[1]+' bits)      '
                #+new_substitution[2]+'         '+new_substitution[3])

            #else:
                #item = QListWidgetItem('               '
                #+new_substitution[2]+'         '+new_substitution[3])
                #item.setIcon(self.kind_Sbox[1])
            
            #self.widget_list_new_operation.addItem(item)    

            #deleting line edits data in order to put the next data
            #self.size_Sbox.clear()
            #self.input_Sbox.clear()
            #self.output_Sbox.clear()
            #self.kind_Sbox = ['', '']
            
                    item = QListWidgetItem('S ('+self.new_operations[i][1]+' bits)      '
                        +self.new_operations[i][2]+'         '+self.new_operations[i][3])

                    self.widget_list_new_operation.addItem(item)    

                    #deleting line edits data in order to put the next data
                    self.size_Sbox.clear()
                    self.input_Sbox.clear()
                    self.output_Sbox.clear()


                elif ( self.new_operations[i][0] == 'P' ):
                    item = QListWidgetItem( 'P'+str(self.new_operations[i][1]+1)+'                 '+
                        self.new_operations[i][2])

                    self.widget_list_new_operation.addItem(item)    

                    #deleting line edits data in order to put the next data
                    self.permutation.clear()

                    
    #this function closes the application
    def quitFile(self):
        sys.exit(0)
#======================end of slot function related to menubar==========================================

#=================================slot functions=======================================================

    #this slot function insert data from spin_box and radio_buttons in the block_cipher
    def insert_spin_radio_in_block_cipher(self, status):
        
        #insert amount of round in block_cipher
        if status == 'round_amount':
            self.round_kind_amount[0] = str(self.spin_box.value())

            
        #insert kind of cryptanalysis in block_cipher    
        elif status == 'differential':
            self.round_kind_amount[1] = 'differential'

        elif status == 'linear':
            self.round_kind_amount[1] = 'linear'



    #this slot function by clicking pushbutons, inserts data from lineEdits in to related lists and widgetlists 
    def insert_data_in_list_and_widgetList(self, status):

        #insert idices and size of branches from lineEdits in to self.widget_list_new_branch & self.branches_indices
        if status == 'insert_new_branch':
            branch_indice = ['', '']
            branch_indice[0] = str(self.branch_indice.text())
            branch_indice[1] = str(self.branch_size.text())

            #==========warning=======================================================
            if branch_indice[0] == '':
                QMessageBox.warning(self, 'warning', 'the indice of new branch is not defined', QtWidgets.QMessageBox.Ok)
                return

            for i in range(len(self.branches_indices)):
                if branch_indice[0] == self.branches_indices[i][0]:
                    QMessageBox.warning(self, 'warning', 'this branch is defined before', QtWidgets.QMessageBox.Ok)
                    return

            if branch_indice[1] == '':
                QMessageBox.warning(self, 'warning', 'the nubember of bits of new branch is not determined', QtWidgets.QMessageBox.Ok)
                return

            if int(branch_indice[1]) <= 0:
                QMessageBox.warning(self, 'warning', 'the number of branch must be positive', QtWidgets.QMessageBox.Ok)
                return
            #==========endo of warning===============================================

            self.branches_indices.append(branch_indice)
            
            self.widget_list_new_branch.addItem('                   '+ branch_indice[0]+
            '                        '+branch_indice[1])

            #deleting line edit data in order to put the next data
            self.branch_indice.clear()

            
        #insert corresponded input output from lineEdits in to self.widget_list_input_output & self.input_output_indices
        if status == 'insert_input_output':
            input_output_indice = ['', '']
            input_output_indice[0] = str(self.input_branch.text())
            input_output_indice[1] = str(self.output_branch.text())

            #==========warning==================================================================
            if input_output_indice[0] == '':
                QMessageBox.warning(self, 'warning', 'the indice of input branch is not defined', QtWidgets.QMessageBox.Ok)
                return

            if input_output_indice[1] == '':
                QMessageBox.warning(self, 'warning', 'the number of output branch is not defined', QtWidgets.QMessageBox.Ok)
                return     
            #==========endo of warning=========================================================

            self.input_output_indices.append(input_output_indice)
            
            self.widget_list_input_output.addItem('                   '+ input_output_indice[0]+
            '                        '+input_output_indice[1])

            #deleting line edits data in order to put the next data
            self.input_branch.clear()
            self.output_branch.clear()
        
        #insert corresponded permutation from lineEdit in to self.widget_list_permutation & self.permutation & self.cb_4
        if status == 'insert_permute':
            read_permutation = self.permutation.toPlainText()
            permutation = []
            for line in read_permutation.split(','):
                permutation.append(line)

            #==========warning==================================================================
            for i in range(len(permutation)):
                if str(i) not in permutation:
                    QMessageBox.warning(self, 'warning', 'the defined permutation is invalid', QtWidgets.QMessageBox.Ok)
                    return
            for line in self.permutations:    
                if permutation == line:
                    QMessageBox.warning(self, 'warning', 'this permutation is defined previousely', QtWidgets.QMessageBox.Ok)
                    return     
            #==========endo of warning=========================================================

            self.cb_4.addItem('P'+str(self.permut_num))
            self.cb_4.activated.connect(lambda: self.insert_comboBoxes_detatils_in_listWidget('permutation'))
            
            self.permutations.append(permutation)

            input_permutation = str(0)
            for i in range(len(permutation)-1):
                input_permutation += (', '+str(i+1))

            output_permutation = permutation[0]
            for i in range(len(permutation)-1):
                output_permutation += (', '+permutation[i+1])
            
            self.widget_list_permutation.addItem( 'P'+str(self.permut_num)+' ('+ input_permutation+') = ('
            + output_permutation +')' )

            self.permut_num += 1
            self.permutation_tag.setText('P'+str(self.permut_num ))

            #deleting line edits data in order to put the next data
            self.permutation.clear()


        #insert details of operations from lineEdits in to self.widget_list_new_operation & self.new_operations
        if status == 'insert_operation_details':      
            new_operation = ['', '', '', '']
            new_operation [0] = self.icon_operation[0]
            new_operation [1] = str(self.input1_indice.text())
            new_operation [2] = str(self.input2_indice.text())
            new_operation [3] = str(self.output_indice.text())

            #==========warning=======================================================
            if new_operation [0] == '':
                QMessageBox.warning(self, 'warning', 'the kind of operation is not determined', QtWidgets.QMessageBox.Ok)
                return
            
            if new_operation [1] == '':
                QMessageBox.warning(self, 'warning', 'the indice of first input is not determined', QtWidgets.QMessageBox.Ok)
                return

            if new_operation [2] == '':
                QMessageBox.warning(self, 'warning', 'the indice of second input is not determined', QtWidgets.QMessageBox.Ok)
                return

            if new_operation [3] == '':
                QMessageBox.warning(self, 'warning', 'the indice of output is not determined', QtWidgets.QMessageBox.Ok)
                return      
            #==========endo of warning===============================================

            self.new_operations.append(new_operation)
            
            item = QListWidgetItem('              '+ new_operation[1]+
            '          '+ new_operation[2]+'          '+ new_operation[3])
            
            item.setIcon(self.icon_operation[1])
            self.widget_list_new_operation.addItem(item)

            #deleting line edits data in order to put the next data
            self.input1_indice.clear()
            self.input2_indice.clear()
            self.output_indice.clear()


        #insert details of rotation from lineEdits in to self.widget_list_new_operation & self.new_operations 
        if status == 'insert_rotation_details':
            new_rotation = ['', '', '']
            new_rotation[0] = self.icon_rotation[0]
            new_rotation[1] = str(self.amount_rotate.text())
            new_rotation[2] = str(self.rotated_branch_indice.text())

            #==========warning=======================================================
            if new_rotation [0] == '':
                QMessageBox.warning(self, 'warning', 'the kind of transfer is not determined', QtWidgets.QMessageBox.Ok)
                return

            if new_rotation [1] == '':
                QMessageBox.warning(self, 'warning', 'the amount of transfer is not determined', QtWidgets.QMessageBox.Ok)
                return

            if new_rotation [2] == '':
                QMessageBox.warning(self, 'warning', 'the indice of branch is not determined', QtWidgets.QMessageBox.Ok)
                return
            #==========endo of warning===============================================

            self.new_operations.append(new_rotation)

            item = QListWidgetItem('            ( '+ new_rotation[1]+' )'+
            '        '+ new_rotation[2])

            item.setIcon(self.icon_rotation[1])
            self.widget_list_new_operation.addItem(item)    

            #deleting line edits data in order to put the next data
            self.amount_rotate.clear()
            self.rotated_branch_indice.clear()


        #insert details of substitution from lineEdits in to self.widget_list_new_operation & self.new_operations 
        if status == 'insert_substitution_details':
            
            #==========warning=======================================================
            if self.kind_Sbox[0] != '' and str(self.size_Sbox.text()) != '':
                QMessageBox.warning(self, 'warning', 'using two identical branch in S-box is not valid', QtWidgets.QMessageBox.Ok)
                return
            #==========endo of warning===============================================

            if str(self.size_Sbox.text()) != '':  
                self.kind_Sbox[0] = str(self.size_Sbox.text())
            
            new_substitution = ['S', '', '', '']

            new_substitution[1] = self.kind_Sbox[0]
            new_substitution[2] = str(self.input_Sbox.text())
            new_substitution[3] = str(self.output_Sbox.text())

            #==========warning=======================================================
            if new_substitution [1] == '':
                QMessageBox.warning(self, 'warning', 'the size of S-box is not determined', QtWidgets.QMessageBox.Ok)
                return

            if new_substitution [2] == '':
                QMessageBox.warning(self, 'warning', 'the input of S-box is not determined', QtWidgets.QMessageBox.Ok)
                return

            if new_substitution [3] == '':
                QMessageBox.warning(self, 'warning', 'the output of S-box is not determined', QtWidgets.QMessageBox.Ok)
                return

            if new_substitution [2] == new_substitution [3]:
                QMessageBox.warning(self, 'warning', 'the statement is not valid', QtWidgets.QMessageBox.Ok)
                return
            #==========endo of warning===============================================

            self.new_operations.append(new_substitution)

            if self.kind_Sbox[1] == '': #the Sbox is public (not specialized...)
                item = QListWidgetItem('S ('+new_substitution[1]+' bits)      '
                +new_substitution[2]+'         '+new_substitution[3])

            else:
                item = QListWidgetItem('               '
                +new_substitution[2]+'         '+new_substitution[3])
                item.setIcon(self.kind_Sbox[1])
            
            self.widget_list_new_operation.addItem(item)    

            #deleting line edits data in order to put the next data
            self.size_Sbox.clear()
            self.input_Sbox.clear()
            self.output_Sbox.clear()
            self.kind_Sbox = ['', '']

              
        #insert details of permutation from lineEdits in to self.widget_list_new_operation & self.new_operations 
        if status == 'insert_permutation_details':
            new_permutation = ['P', '', '']
            new_permutation[1] = self.icon_permutation[0]
            new_permutation[2] = str(self.branch_indice_Pbox.text())

            #==========warning=======================================================
            if new_permutation [1] == '':
                QMessageBox.warning(self, 'warning', 'the kind of P-box is not determined', QtWidgets.QMessageBox.Ok)
                return

            if new_permutation [2] == '':
                QMessageBox.warning(self, 'warning', 'the indice of branch is not determined', QtWidgets.QMessageBox.Ok)
                return
            #==========endo of warning===============================================

            self.new_operations.append(new_permutation)

            item = QListWidgetItem( self.icon_permutation[1]+'                 '+
            new_permutation[2])

            self.widget_list_new_operation.addItem(item)    

            #deleting line edits data in order to put the next data
            self.branch_indice_Pbox.clear()


    #this function deletes the item which is double clicked from widget list and its related list 
    def delete_widget_list_doubleClicked(self, status):
        
        if status == 'new_branch_list':
            curItem = self.widget_list_new_branch.currentItem()
            row_indice = self.widget_list_new_branch.row(curItem)
            del self.branches_indices[row_indice]
            self.widget_list_new_branch.takeItem(row_indice)

        elif status == 'input_output_list':
            curItem = self.widget_list_input_output.currentItem()
            row_indice = self.widget_list_input_output.row(curItem)
            del self.input_output_indices[row_indice]
            self.widget_list_input_output.takeItem(row_indice)

        elif status == 'new_operation_list':
            curItem = self.widget_list_new_operation.currentItem()
            row_indice = self.widget_list_new_operation.row(curItem)
            del self.new_operations[row_indice]
            self.widget_list_new_operation.takeItem(row_indice)



    #this slot function insert kind of operation or rotation data (from combobox) in "self.insert_operation" list 
    def insert_comboBoxes_detatils_in_listWidget(self, status):

        #insert kind of operation and its icon in "self.icon_operation"
        if status == 'operation':
            if str(self.cb_1.currentText()) == '':
                self.icon_operation = ['xor', self.xor_icon]
                
            elif str(self.cb_1.currentText()) == ' ':
                self.icon_operation = ['threeFork', self.threeFork_icon]
                
            elif str(self.cb_1.currentText()) == '  ':
                self.icon_operation = ['modularAdd', self.modularAdd_icon]
                
            elif str(self.cb_1.currentText()) == '   ':
                self.icon_operation = ['and', self.and_icon]


        #insert kind of rotation and its icon in "self.icon_rotation"
        if status == 'rotation':
            if str(self.cb_2.currentText()) == '':
                self.icon_rotation = ['rotl', self.rotl_icon]     

            if str(self.cb_2.currentText()) == ' ':
                self.icon_rotation = ['rotr', self.rotr_icon]
                
                
        #insert kind of Sbox and its icon in "self.icon_permutation"
        #if status == 'kind_Sbox':
            #if str(self.cb_3.currentText()) == '':
                #'000' is the symbole of and operation here
                #self.kind_Sbox = ['000', self.and_icon]     
            

        #insert kind of permutation and its icon in "self.icon_permutation"
        if status == 'permutation':
            text = self.cb_4.currentText()
            self.icon_permutation = [int(text[1:])-1, text]


    #this slot function is related t2 push_butt
    def execude_window_pushButtons(self, status):
        #==========warnings=======================================================
        if self.round_kind_amount [1] == '':
            QMessageBox.warning(self, 'warning', 'the kind of analyze is not determined', QtWidgets.QMessageBox.Ok)
            return

        if self.branches_indices == []:
            QMessageBox.warning(self, 'warning', 'there is no information in "create branch" sectioon ', QtWidgets.QMessageBox.Ok)
            return

        if self.input_output_indices == []:
            QMessageBox.warning(self, 'warning', 'there is no information in "mutual indices" section ', QtWidgets.QMessageBox.Ok)
            return

        if self.new_operations == []:
            QMessageBox.warning(self, 'warning', 'there is no information in "describe block cipher" section ', QtWidgets.QMessageBox.Ok)
            return


        check_warnings = WarningError(self.round_kind_amount, self.branches_indices, self.input_output_indices, self.permutations, self.new_operations)

        if check_warnings.status  == False:
            QMessageBox.warning(self, 'warning', check_warnings.warning_message, QtWidgets.QMessageBox.Ok)
            return
        #==========end of warning===============================================
        
        #constructing the copy of self.new_branches, the original one must doesnt change
        branches_indices = []
        for line in self.branches_indices:
            branches_indices.append(list(line))
            
        key_MOdular_add_diff = check_warnings.key_add_diff#the list of "keys" which are coperated in modular_add
         
        self.organize_block_cipher()
############################################################## execute buttons ############################################################################
        if status == 'gurobi_equations':
            #print(self.block_cipher)
            self.gurobi_equations = MILPGenerator(self.block_cipher, branches_indices, self.permutations, key_MOdular_add_diff, 'gurobi_equations')
            #self.gurobi_equations.show()
            QMessageBox.information(self, 'information', 'the MILP model compatibale with Gurobi solver with the name of ( Gurobi-model-' + 
                self.round_kind_amount [1] + '-analysis-of-' + self.round_kind_amount [0] + '-rounds.lp )' + ' is constructed' , QtWidgets.QMessageBox.Ok)
            
            self.block_cipher = ['']
            
        elif status == 'Cplex_equations':
            #print(self.block_cipher)
            self.Cplex_equations = MILPGenerator(self.block_cipher, branches_indices, self.permutations, key_MOdular_add_diff, 'Cplex_equations')
            self.Cplex_equations.show()
            self.block_cipher = ['']
            
        elif status == 'analyze_model':
            #print(self.block_cipher)
            self.analyze_model = MILPGenerator(self.block_cipher, branches_indices, self.permutations, key_MOdular_add_diff, 'analyze_model')
            self.t4.setEnabled(True)
            self.block_cipher = ['']
            
        elif status == 'variables_char':
            self.variables_char = MILPGenerator(self.block_cipher, branches_indices, self.permutations, key_MOdular_add_diff, 'variables_char')
            self.variables_char.show()
            self.t4.setEnabled(False)
            self.block_cipher = ['']
            
        elif status == 'impossible_trails':
            self.impossible_trails = MILPGenerator(self.block_cipher, branches_indices, self.permutations, key_MOdular_add_diff, 'impossible_trails')
            #self.impossible_trails.show()
            self.block_cipher = ['']
            
        elif status == 'log_equations':
            #print(self.block_cipher)
            self.MILP_log_equations = MILPGenerator(self.block_cipher, branches_indices, self.permutations, key_MOdular_add_diff, 'log_equations')
            self.MILP_log_equations.show()
            self.block_cipher = ['']
        
        
#============================================end of slot functions================================================ 

if __name__ == '__main__':
    
    def main():
        
        app = QtWidgets.QApplication(sys.argv)  
        ex = ARXCryptanalyserWindow()
        ex.show()
        app.exec_()
        #sys.exit(app.exec_())
        
    main()
