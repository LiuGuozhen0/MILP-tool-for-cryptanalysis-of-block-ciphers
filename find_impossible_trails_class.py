import sys 
from PyQt5.QtWidgets import *
from gurobipy import *
from io import *


class findImpossibleTrails(QWidget):
    """this class reads the lp file and finds the impossible trails on them and can prints the paradox variables """
    def __init__(self, all_variables, constraints_of_each_round): 
        QWidget.__init__(self)
        
        
        
        self.all_variables = all_variables #this list is contaned of all variables{
            #self.all_variables[0] = objective variables
            #self.all_variables[1] = plain text variables
            #self.all_variables[2] = cipher text variables
            #self.all_variables[3] = all variables except plaintext and ciphertext}
        self.constraints_of_each_round = constraints_of_each_round# this list is contaned the constraints of each round separately       
        
        self.input_indices = []#this list is contained of indices of inputs, which should be tested
        self.output_indices = []#this list is contained of indices of outputs, which should be tested
        self.input_output_impossibles = []#this list is contaned of all obtained impossibles input-output
        
        self.setWindowTitle('finding impossible input and output')
        #self.setGeometry(250,70, 800, 625)
        #self.setFixedSize(800, 560)
        self.setFixedSize(400, 560)
        
        self.widget_list_impossibles = QListWidget(self)
        #self.widget_list_impossibles.setGeometry(5,70,250,300)
        self.widget_list_impossibles.setGeometry(5,70,390,300)
        
        #self.widget_list_report = QListWidget(self)
        #self.widget_list_report.setGeometry(255,70,135,300)
        #self.widget_list_report.itemClicked.connect(self.find_contradictry_variables)
        
################        
        #item1 = QListWidgetItem('                   '+'0'+'                                   '+'15')
        #self.widget_list_impossibles.addItem(item1)
        #item2 = QListWidgetItem('یافتن متغیرهای متناقض')
        #self.widget_list_report.addItem(item2)
        #self.input_output_impossibles.append([0, 15])
###############
        
        title_imposible_input = QLabel('the indice (bit) of nonzero input', self)
        title_imposible_input.move(10,50)
        
        title_imposible_output = QLabel('the indice of nonzero output', self)
        title_imposible_output.move(250,50)
        
        #title_imposible_report = QLabel('بررسی جزییات', self)
        #title_imposible_report.move(285,50)
        
        self.t1 =QPushButton('search 1', self)
        self.t1.setGeometry(20,380, 100, 25)
        self.t1.clicked.connect(lambda: self.customize_input_output_indices('type1'))
        
        self.t2 =QPushButton('search 2', self)
        self.t2.setGeometry(150,380, 100, 25)
        self.t2.clicked.connect(lambda: self.customize_input_output_indices('type2'))
        
        self.t3 =QPushButton('search 3', self)
        self.t3.setGeometry(280,380, 100, 25)
        self.t3.clicked.connect(lambda: self.customize_input_output_indices('type3'))
        
        
        self.t4 =QPushButton('search 4', self)
        self.t4.setGeometry(20,410, 100, 25)
        self.t4.clicked.connect(lambda: self.customize_input_output_indices('type4'))
       
        self.t5 =QPushButton('search 5', self)
        self.t5.setGeometry(150,410, 100, 25)
        self.t5.clicked.connect(lambda: self.customize_input_output_indices('type5'))
        
        self.t6 =QPushButton('search 6', self)
        self.t6.setGeometry(280,410, 100, 25)
        self.t6.clicked.connect(lambda: self.customize_input_output_indices('type6'))
        

        self.t7 =QPushButton('search 7', self)
        self.t7.setGeometry(20,440, 100, 25)
        self.t7.clicked.connect(lambda: self.customize_input_output_indices('type7'))
        
        self.t8 =QPushButton('search 8', self)
        self.t8.setGeometry(150,440, 100, 25)
        self.t8.clicked.connect(lambda: self.customize_input_output_indices('type8'))  
        
        self.t9 =QPushButton('search 9', self)
        self.t9.setGeometry(280,440, 100, 25)
        self.t9.clicked.connect(lambda: self.customize_input_output_indices('type9'))
        

                        
        
        '''
        #====creating the find_contradictry_variables box==========================
        find_contradictry_variables_box = QGroupBox(self)
        find_contradictry_variables_box.setGeometry(400,5,395,550)
        title_find_contradictry = QLabel('جستجوی مشخصه های متناقض برای ورودی-خروجی ناممکن به دست آمده', self)
        title_find_contradictry.move(425,15)
        
        title_1= QLabel('متغیرهای به دست آمده برای نیمه اول مدل', self)
        title_1.move(495,45)
        self.log_t1 = QTextBrowser(self)
        self.log_t1.setGeometry(405,60, 385, 145)
        
        title_2= QLabel('متغیرهای خروجی نیمه اول', self)
        title_2.move(540,210)
        self.log_t2 = QTextBrowser(self)
        self.log_t2.setGeometry(405,225, 385, 70)
        
        title_3= QLabel('متغیرهای ورودی نیمه دوم', self)
        title_3.move(540,300)
        self.log_t3 = QTextBrowser(self)
        self.log_t3.setGeometry(405,315, 385, 70)
        
        title_4= QLabel('متغیرهای به دست آمده برای نیمه دوم مدل', self)
        title_4.move(495,390)
        self.log_t4 = QTextBrowser(self)
        self.log_t4.setGeometry(405,405, 385, 145)
        #====creating the find_contradictry_variables box==========================
        '''
       
    
    #this function sets the 'self.input_indices' and 'self.input_indices' ...
    #-> and finds impossible input and output
    def customize_input_output_indices(self, status):
        
        #the callback function for gurobi
        def mycallback(model,where) :
            if where == GRB.Callback.MIP :
                best = model.cbGet(GRB.Callback.MIP_OBJBST)
                if best <= 400:
                    model.terminate()
        
        
        i = range(len(self.all_variables[1]))
        
        if status == 'type1':
            
            for line in i[0 : -1 : 3]:
                self.input_indices.append(line)      
            for line in i[0 : -1 : 3]:
                self.output_indices.append(line)
            self.t1.setEnabled(False)
                
        elif status == 'type2':
            
            for line in i[0 : -1 : 3]:
                self.input_indices.append(line)      
            for line in i[1 : -1 : 3]:
                self.output_indices.append(line)
            self.t2.setEnabled(False)
            
        elif status == 'type3':
            
            for line in i[0 : -1 : 3]:
                self.input_indices.append(line)      
            for line in i[2 : -1 : 3]:
                self.output_indices.append(line)
            self.t3.setEnabled(False)
                
        elif status == 'type4':
            
            for line in i[1 : -1 : 3]:
                self.input_indices.append(line)      
            for line in i[0 : -1 : 3]:
                self.output_indices.append(line)
            self.t4.setEnabled(False)
                
        elif status == 'type5':
            
            for line in i[1 : -1 : 3]:
                self.input_indices.append(line)      
            for line in i[1 : -1 : 3]:
                self.output_indices.append(line)
            self.t5.setEnabled(False)
                
        elif status == 'type6':
            
            for line in i[1 : -1 : 3]:
                self.input_indices.append(line)      
            for line in i[2 : -1 : 3]:
                self.output_indices.append(line)
            self.t6.setEnabled(False)
            
        elif status == 'type7':
            
            for line in i[2 : -1 : 3]:
                self.input_indices.append(line)      
            for line in i[0 : -1 : 3]:
                self.output_indices.append(line)
            self.t7.setEnabled(False)
                
        elif status == 'type8':
            
            for line in i[2 : -1 : 3]:
                self.input_indices.append(line)      
            for line in i[1 : -1 : 3]:
                self.output_indices.append(line)
            self.t8.setEnabled(False)
                
        elif status == 'type9':
            
            for line in i[2 : -1 : 3]:
                self.input_indices.append(line)      
            for line in i[2 : -1 : 3]:
                self.output_indices.append(line)
            self.t9.setEnabled(False)
                        
        try:
                
            imposible = [] #list of imposible trails
            #input = [0, 15, 31, 47, 63], output = [0, 7, 23, 39, 55] for 17 rounds of zerocorelation of hight
            #input = [0, 16, 32], output = [56, 8, 24] for 17 rounds of impossible of hight
                
            for i in self.input_indices:
                for j in self.output_indices:  
                        
                    #====================adding the nonzero plaintext/ciphertext variable to the model==============
                    condition1 = self.all_variables[1][i]+' = 1'
                    condition2 = self.all_variables[2][j]+' = 1'
            
                    with open('impossible-trails-model.lp') as f:
                        newText=f.read().replace('condition1', condition1).replace('condition2', condition2)
                    with open('impossible-trails-model.lp', "w") as f:
                        f.write(newText)
                    #====================end of adding the nonzero plaintext/ciphertext variable to the model======
                        
                    m = read('impossible-trails-model.lp')
                    m.Params.LogFile='impossible-trails-model.log'
                    print('*********************************************************')
                    print('The indice of nonzero element of plaintext = '+ str(i))
                    print('The indice of nonzero element of ciphertext = '+ str(j)+'\n')
                    
                    m.optimize(mycallback)
                        
                    if m.status == 3:
                        
                        item1 = QListWidgetItem('                          '+str(i)+
                                                '                                                                            '+str(j))
                        self.widget_list_impossibles.addItem(item1)
                        
                        #item2 = QListWidgetItem('یافتن متغیرهای متناقض')
                        #self.widget_list_report.addItem(item2)
                        
                        input_output_impossibles = []
                        input_output_impossibles.append(i)
                        input_output_impossibles.append(j)
                        self.input_output_impossibles.append(input_output_impossibles)
                        
                        
                    with open('impossible-trails-model.lp') as f:
                        newText=f.read().replace(condition1, 'condition1').replace(condition2, 'condition2')
                    with open('impossible-trails-model.lp', "w") as f:
                        f.write(newText)        
            
        except GurobiError: 
            print('Error reported')
 
       
        self.input_indices = []
        self.output_indices = []
        
        
    def find_contradictry_variables(self):
        
        mid_r = len(self.all_variables[3]) // 2#half of the number of rounds
        if len(self.all_variables[3]) % 2 != 0 :
            mid_r = (len(self.all_variables[3]) // 2 )+ 1
                    
        midvars = self.all_variables[3][mid_r - 1][0]
        curItem = self.widget_list_report.currentItem()
        indice = self.widget_list_report.row(curItem)
   
       #==============constructing the first half MILP model===================================
        filename = 'first-half-model.lp'
        o=open(filename,'w')
        o.write('Minimize')
        o.write('\n')  
        
        #defining objective function
        o.write(self.all_variables[0][0])
        
        o.write('\n')
        o.write('\n')
        o.write('Subject To')
        o.write('\n')
        
        #defining a constraint(plain tex must be equal to one)
        o.write(self.all_variables[1][0])
        for line in self.all_variables[1][1:]:
            o.write(' + '+line)
        o.write(' = 1') 
        o.write('\n')
        o.write(self.all_variables[1][ self.input_output_impossibles[indice][0] ]+' = 1')
        o.write('\n\n')
        
        for line1 in self.constraints_of_each_round[0: mid_r]:
            for line2 in line1:
                o.write(line2)
                o.write('\n')
            
        o.write('\n')
        o.write('\n')
        o.write('Binary')
        o.write('\n')
        o.write('\n')
        
        #========printing all the variables in the lp file===============   
        #printing the plaintext variables
        for j in range(len(self.all_variables[1])):
            o.write(self.all_variables[1][j] +'\n')
        
        #printing the rest of the variables
        for line1 in self.all_variables[3][0: mid_r]:
            for line2 in line1:
                for line3 in line2:
                    o.write(line3 +'\n')
        #========end of printing all the variables in the lp file======
        
        o.write('End')
        o.close()
        #==============end of constructing the first half MILP model=============================
        #****************************************************************************************
        #==============constructing the second half MILP model===================================
        filename = 'second-half-model.lp'
        o=open(filename,'w')
        o.write('Minimize')
        o.write('\n')  
        
        #defining objective function
        o.write(self.all_variables[0][-1])
        
        o.write('\n')
        o.write('\n')
        o.write('Subject To')
        o.write('\n')
                
        #defining a constraint(cipher tex must be equal to one)
        o.write(self.all_variables[2][0])
        for line in self.all_variables[2][1:]:
            o.write(' + '+line)
        o.write(' = 1')
        o.write('\n')
        o.write(self.all_variables[2][ self.input_output_impossibles[indice][1] ]+' = 1')
        o.write('\n\n')
        
        for line1 in self.constraints_of_each_round[mid_r:-1]:
            for line2 in line1:
                o.write(line2)
                o.write('\n')
            
        o.write('\n')
        o.write('\n')
        o.write('Binary')
        o.write('\n')
        o.write('\n')
        
        #========printing all the variables in the lp file===============   
        #printing the ciphertext variables
        for j in range(len(self.all_variables[2])):
            o.write(self.all_variables[2][j] +'\n')
        
        #printing the rest of the variables
        for line1 in self.all_variables[3][mid_r : -1]:
            for line2 in line1:
                for line3 in line2:
                    o.write(line3 +'\n')
        #========end of printing all the variables in the lp file======
        
        o.write('End')
        o.close()
        #==============end of constructing the second half MILP model=============================        
 
       
        
        #=========optimizing the files============================
        self.m1 = read('first-half-model.lp')            
        self.m1.optimize()
        
        vars_char_file1 = [] 
        var_char = ['','']
        for v in self.m1.getVars():
            var_char[0] = v.varName
            var_char[1] = v.x
            vars_char_file1.append(var_char)
            var_char = ['','']
            
        
        self.m2 = read('second-half-model.lp')            
        self.m2.optimize()
        
        vars_char_file2 = [] 
        var_char = ['','']
        for v in self.m2.getVars():
            var_char[0] = v.varName
            var_char[1] = v.x
            vars_char_file2.append(var_char)
            var_char = ['','']
        #=========end of optimizing the files====================
        
        #======printing the amounts variables in text-browsers============
        for line in vars_char_file1:
            self.log_t1.append('        '+str(line[0])+'  =  '+str(line[1]))
            self.log_t1.append('\n')
            
        for line1 in midvars:
            for line2 in vars_char_file1:
                if line1 == line2[0]:
                    self.log_t2.append('        '+str(line2[0])+'  =  '+str(line2[1]))
                    self.log_t2.append('\n')
                    break
                
        for line1 in midvars:
            for line2 in vars_char_file2:
                if line1 == line2[0]:
                    self.log_t3.append('        '+str(line2[0])+'  =  '+str(line2[1]))
                    self.log_t3.append('\n')
                    break
                
        for line in vars_char_file2:
            self.log_t4.append('        '+str(line[0])+'  =  '+str(line[1]))
            self.log_t4.append('\n')
        #======end of printing the amounts variables in text-browsers======


        
        
            

