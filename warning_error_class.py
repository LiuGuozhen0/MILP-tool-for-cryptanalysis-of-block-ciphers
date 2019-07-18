#import os
#import sys
#from PyQt5 import QtCore, QtWidgets, Qt
#from PyQt5.QtWidgets import *
#from PyQt5.QtGui import *
#from __future__ import division



class WarningError():
    """this class investigates input data to detect defects """
    def __init__(self, round_kind_amount, branches_indices, input_output_indices, permutations, new_operations):
        super().__init__()

        
        self.a_list = branches_indices
        self.b_list = input_output_indices
        self.c_list = new_operations
        self.permutations = permutations 
        
        self.a_size = len(self.a_list)
        self.b_size = len(self.b_list)
        self.c_size = len(self.c_list)

        #the keies that are copperated in modular_Add need to be detected...
        #->because they are needed tobe zero in differential cryptanalysis
        self.key_add_diff = []


        #the self.comprehensive_analysis checks that the decripted block_cipher is comprehensive analysis...
        #->or poor differential or poor linear analysis. if it is not comprehensive, the function "check_branch_is_used_correctly" ...
        #->&  and some part of "check_operation_and_inputOutput_is_correct" must not be applied
        self.comprehensive_analysis = False
        count_xor = 0
        count_threeFork = 0
        for line in self.c_list:

            if 'xor' in line[0]:
                count_xor = 1

            if 'threeFork' in line[0]:
                count_threeFork = 1
                
            main_count = count_xor + count_threeFork

            if main_count == 2:
                self.comprehensive_analysis = True
                break
            

        self.status = True #if we are faced with an error message, this variable is converted to 'False' & doesn't let the program continues
        self.warning_message = ''

        #=====checking that 'xor' is apllied in differential analysis & threeFork is apllied in linear analysis=========
        if ( round_kind_amount[1] == 'differential' and
             count_xor == 0 ):
            self.status = False
            self.warning_message ='the XOR operation is not used in differential cryptanalysis'
            return

        if ( round_kind_amount[1] == 'linear' and
             count_threeFork == 0 ):
            self.status = False
            self.warning_message ='the three-fork operation is not used in linear cryptanalysis'
            return
        #=====end of checking that 'xor' is apllied in differential analysis & threeFork is apllied in linear analysis==
        

        
        self.check_branch_is_defined()

        if self.status == True:
            self.check_operation_and_inputOutput_is_correct()

        if self.status == True:
            self.check_branch_is_used_correctly()

            

    '''this function checks self.b_list & self.c_list to detect that they don't use new branch '''
    def check_branch_is_defined(self):
        defined = False
        
        #checking in self.b_list
        for i in range(self.b_size):
            
            for j in range(self.a_size):
                if self.b_list[i][0] == self.a_list[j][0]:
                    defined = True
                    break
            if defined == False:
                self.status = False
                self.warning_message ='the size of the branch (' +self.b_list[i][0]+ ') is not determined'
                return

            defined = False
            for j in range(self.a_size):
                if self.b_list[i][1] == self.a_list[j][0]:
                    defined = True
                    break
            if defined == False:
                self.status = False
                self.warning_message ='the size of the branch (' +self.b_list[i][1]+ ') is not determined'
                return
            defined = False


        #checking in self.c_list
        for i in range(self.c_size):
            
            #checking the rotations
            if self.c_list[i][0] == 'rotl' or self.c_list[i][0] == 'rotr':
                for j in range(self.a_size):
                    if self.c_list[i][2] == self.a_list[j][0]:
                        defined = True
                        break
                if defined == False:
                    self.status = False
                    self.warning_message ='the size of the branch (' +self.c_list[i][2]+ ') is not determined'
                    return
                defined = False
                

            #checking the operations
            elif self.c_list[i][0] == 'xor' or self.c_list[i][0] == 'threeFork' or self.c_list[i][0] == 'modularAdd': 
                #checking for first input
                for j in range(self.a_size):
                    if self.c_list[i][1] == self.a_list[j][0]:
                        defined = True
                        break
                if defined == False:
                    self.status = False
                    self.warning_message ='the size of the branch (' +self.c_list[i][1]+ ') is not determined'
                    return

                #checking for second input
                defined = False
                for j in range(self.a_size):
                    if self.c_list[i][2] == self.a_list[j][0]:
                        defined = True
                        break
                if defined == False:
                    self.status = False
                    self.warning_message ='the size of the branch (' +self.c_list[i][2]+ ') is not determined'
                    return

                #checking for output
                defined = False
                for j in range(self.a_size):
                    if self.c_list[i][3] == self.a_list[j][0]:
                        defined = True
                        break
                if defined == False:
                    self.status = False
                    self.warning_message ='the size of the branch (' +self.c_list[i][3]+ ') is not determined'
                    return
                defined = False


            #checking the S-boxs
            if self.c_list[i][0] == 'S':

                #checking for the input
                for j in range(self.a_size):
                    if self.c_list[i][2] == self.a_list[j][0]:
                        defined = True
                        break
                if defined == False:
                    self.status = False
                    self.warning_message ='the size of the branch (' +self.c_list[i][2]+ ')is not determined'
                    return
                defined = False

                #checking for output
                defined = False
                for j in range(self.a_size):
                    if self.c_list[i][3] == self.a_list[j][0]:
                        defined = True
                        break
                if defined == False:
                    self.status = False
                    self.warning_message ='the size of the branch (' +self.c_list[i][3]+ ') is not determined'
                    return
                defined = False


            #checking the P-boxs
            if self.c_list[i][0] == 'P':

                #checking for the branch
                for j in range(self.a_size):
                    if self.c_list[i][2] == self.a_list[j][0]:
                        defined = True
                        break
                if defined == False:
                    self.status = False
                    self.warning_message ='the size of the branch (' +self.c_list[i][2]+ ') is not determined'
                    return
                defined = False


    '''this function checks that the branch is only one time defined in self.b_size if comprehensive_analysis is true &
    checks self.c_list to detect that the amount of rotation is smaller than the size of branches &
    all of the branches in self.b_list and self.c_list have the same size &
    the size of the defined branches in S-boxes are divisible by the size of the S-box &
    the size of the defined branches in P_boxes are identical to the size of the given permuations
    checks the operands to find a identical branches if self.comprehensive_analysis is True
    '''
    def check_operation_and_inputOutput_is_correct(self):

        #checking the size of the branches in self.b_list are not the same and 
        for i in range(self.b_size):

            #===============checking that the branch is only one time defined in self.b_size if comprehensive_analysis is true==============
            if self.comprehensive_analysis:

                for j in range(self.b_size):
                    if j == i:
                        if self.b_list[i][0] == self.b_list[i][1]:
                            self.status = False
                            self.warning_message =( 'the branch (' +self.b_list[i][0]
                            + ') is used more than one time in the "mutual indices" section')
                            return

                    else:
                        
                        if self.b_list[i][0] in self.b_list[j]:
                            self.status = False
                            self.warning_message =( 'the branch (' +self.b_list[i][0]
                            + ')is used more than one time in the "mutual indices" section')
                            return

                        if self.b_list[i][1] in self.b_list[j]:
                            self.status = False
                            self.warning_message =( 'the branch (' +self.b_list[i][1]
                            + ') is used more than one time in the "mutual indices" section')
                            return
            #===============end of checking that the branch is only one time defined in self.b_size if comprehensive_analysis is true=======
 
            branches_size = []
            for j in range(self.a_size):
                if ( self.b_list[i][0] == self.a_list[j][0] or
                     self.b_list[i][1] == self.a_list[j][0] ):
                    branches_size.append(self.a_list[j][1])
                if len(branches_size) == 2:
                    break

            if(branches_size[0] !=branches_size[1]):
                self.status = False
                self.warning_message = ( 'the size of input branch ' + self.b_list[i][0]
                    + ' is not equal with the size f its corresponded output ranch  ' + self.b_list[i][1]  )
                return
      
        #checking that the amount of rotation is smaller than the size of branches &
        #checking the size of the branches in one operation are not the same
        for i in range(self.c_size):


            if self.c_list[i][0] == 'rotl' or self.c_list[i][0] == 'rotr':

                #===checking that the amount of rotation is smaller than the size of branches========================
                for j in range(self.a_size):#finding the size of branch
                    if self.c_list[i][2] == self.a_list[j][0]:
                        branch_size = int(self.a_list[j][1])
                        break

                if  int(self.c_list[i][1]) > branch_size:
                    self.status = False
                    self.warning_message = ( 'the amount of transfer in the statement (' + self.c_list[i][0]
                    + '    ( ' + self.c_list[i][1] + ' )    ' + self.c_list[i][2] + ') is higher than the size of the branch' )
                    return
                #===end of checking that the amount of rotation is smaller than the size of branches=================


            elif self.c_list[i][0] == 'xor' or self.c_list[i][0] == 'threeFork' or self.c_list[i][0] == 'modularAdd':
                
                #=======checking the size of the branches in one operation are the same==================================
                #finding the size of branches
                branches_size = []
                for k in range(3):
                    for j in range(self.a_size):
                        if self.c_list[i][k+1] == self.a_list[j][0]:
                            branches_size.append(int( self.a_list[j][1]) )
                            break
                
                if  branches_size[0] != branches_size[1] or branches_size[1] != branches_size[2]:
                    self.status = False
                    self.warning_message = ( 'the size of branches in the statement  (' + self.c_list[i][0]
                    + '  ' + self.c_list[i][1] + '  ' + self.c_list[i][2]
                    + '  ' +   self.c_list[i][3] +  ') are not equal' )
                    return
                #=======end of checking the size of the branches in one operation are the same===========================

                #=======checking the operands to find a identical branches if self.comprehensive_analysis is True========
                if self.comprehensive_analysis:
                    if ( self.c_list[i][1] == self.c_list[i][2] or
                         self.c_list[i][2] == self.c_list[i][3] or
                         self.c_list[i][1] == self.c_list[i][3] ):
                        self.status = False
                        self.warning_message = ( 'in the statement (' + self.c_list[i][0]
                            + '  ' + self.c_list[i][1] + '  ' + self.c_list[i][2]
                        + '  ' +   self.c_list[i][3] +  ') there is not any identical branch.' )
                    return
                #=======end of checking the operands to find a identical branches if self.comprehensive_analysis is True=


            elif self.c_list[i][0] == 'S':

                #=======checking the size of the branches in one S-box are the same==================================
                #finding the size of branches
                branches_size = []
                for k in range(2):
                    for j in range(self.a_size):
                        if self.c_list[i][k+2] == self.a_list[j][0]:
                            branches_size.append(int( self.a_list[j][1]) )
                            break

                if  branches_size[0] != branches_size[1]:
                    self.status = False
                    self.warning_message = ( 'اندازه شاخه ها در عبارت  (' + self.c_list[i][0]
                    + '(' + self.c_list[i][1] + ' bits)   ' + self.c_list[i][2]
                    + '   ' +   self.c_list[i][3] +  ') يکسان نمي باشند' )
                    return                    
                #=======checking the size of the branches in one operation are the same==================================

                #====checking the size of the branches to detect that is divisible by the size of the S-box==============
                if ( branches_size[0] % int(self.c_list[i][1]) ) != 0:
                    self.status = False
                    self.warning_message = ( 'the number of branches in the statement  (' + self.c_list[i][0]
                    + '(' + self.c_list[i][1] + ' bits)   ' + self.c_list[i][2]
                    + '   ' +   self.c_list[i][3] +  ') are not divisible on the size of S-box' )
                    return 
                #====checking the size of the branches to detect that is divisible by the size of the S-box==============


            elif self.c_list[i][0] == 'P':

                #=======checking the size of the branch in one P-box to ditect that has the same size of its permutation===
                for j in range(self.a_size):
                        if self.c_list[i][2] == self.a_list[j][0]:
                            branch_size = int( self.a_list[j][1])
                            break

                if branch_size != len( self.permutations[self.c_list[i][1]] ):
                    self.status = False
                    self.warning_message = ( 'the size of branches in the statement  (' + self.c_list[i][0]
                        + str(self.c_list[i][1]+1) + '   ' + self.c_list[i][2]
                        +  ') are not equal to the size of defined P-box' )
                    return

                #=======checking the size of the branch in one P-box to ditect that has the same size of its permutation===
                        
        
    '''this function checks each branch is used in structure exactly 2 times or
    one time if it is used in a modular addition of a key with other branches (if it's comprehensive cryptanalysis) &
    tells us if it's not used at all''' 
    def check_branch_is_used_correctly(self):

        for i in range(self.a_size):
            counter_branch = 0
            operation = ''

            #finding that new_branch how many is used in self.b_size 
            for j in range(self.b_size):
                if self.a_list[i][0]  in self.b_list[j]:
                    counter_branch +=1

            #finding that new_branch how many is used in self.c_size 
            for j in range(self.c_size):
                
                if self.a_list[i][0]  in self.c_list[j]:
                    operation = self.c_list[j][0]
                    if operation != 'rotl' and operation != 'rotr':
                        counter_branch +=1

            #finding the key and inserting it in self.key_add_diff
            if counter_branch == 1 and operation == 'modularAdd':
                self.key_add_diff.append(self.a_list[i][0])

            if self.comprehensive_analysis:
                if( (counter_branch == 1 and operation == 'modularAdd') or
                     counter_branch == 2  ):
                    continue

                else:
                    self.status = False
                    self.warning_message = ( 'the banch (' + self.a_list[i][0]
                     + ') is not used in the structure correctly' )
                    return

            else:
                if counter_branch == 0:
                    self.status = False
                    self.warning_message = ( 'the banch (' + self.a_list[i][0]
                     + ') is not used in the structure correctly' )
                    return

        
                    
                    
            
                
                
                    
                

    
'''def main():
    app = QApplication(sys.argv)

    r = []
    s = ['']
    t = ['']

    ex = WarningErore(r, s ,t)
    ex.show()
    sys.exit(app.exec_())
    
if __name__ == '__main__':
    main()
'''


