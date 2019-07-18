
import os
import sys
from PyQt5 import QtCore, QtWidgets, Qt
from PyQt5.QtWidgets import *
from PyQt5.QtGui import *
from gurobipy import *
from io import *

from find_impossible_trails_class import *

from contextlib import contextmanager
from contextlib import redirect_stdout

    

    
class MILPGenerator(QMainWindow):
    """this class takes the self.block_cipher as a input and gives the MILP equations and characteristics """
    def __init__(self, block_cipher, branches_indices, permutations, key_MOdular_add_diff, status):
        super().__init__()
        
        
        self.block_cipher = block_cipher
        self.branches_indices = branches_indices
        self.permutations = permutations
        self.status = status
        

        if self.block_cipher[0][1] == 'differential':
            self.key_MOdular_add_diff = key_MOdular_add_diff
        else:
            self.key_MOdular_add_diff = []
        
        self.rotations = []#the rotations and operatoins which are affected by rotaions, are inserted in this list
        self.imposed_by_permutation = []#the permutations and operatoins which are affected by permutations, are inserted in this list
        self.forked_vectors = []#this list is contained the indices of forked vectors (not input and output)with thier sizes
        self.dummy_vectors = []#this list is contained the indices of dummy vectors
        self.objective_vectors = []#this list is contained the indices of objective vectors
        self.dummy_diff_modularAdd_vector = []#this list is contained the indices of dummy objective member for differential cryptanalysis
        self.input_output_variables = []#this list is contained all of the inputs-outputs variables except plaintex (output of each round is input of next round), which are cooperated on the model (this list helps to construct the list "self.all_variables"
        self.all_variables = []#this list is contained all of the variables, which are cooperated on the model
        self.block_cipher_all_round = []#this list is contained of description of block_cipher for each round
        #this list is applied in self.constructLogEquations()
        self.equivalent_branches = [] #this list shows the indices of branches which are converted into one branch(the first member of the operation)

        #the self.comprehensive_analysis checks that the decripted block_cipher is comprehensive analysis...
        #->or poor differential or poor linear analysis. if it is not comprehensive, the function "organizeDifferentialLinear()" ...
        #-> must not be applied
        self.comprehensive_analysis = False
        count_xor = 0
        count_threeFork = 0
        for line in self.block_cipher:

            if 'xor' in line[0]:
                count_xor = 1

            if 'threeFork' in line[0]:
                count_threeFork = 1
                
            main_count = count_xor + count_threeFork

            if main_count == 2:
                self.comprehensive_analysis = True
                break

            if 'modularAdd' in line[0]:
                self.kind_objective = 'modularAdd'#the kind of objective function is modular addition

            if 'S' in line[0]:
                self.kind_objective = 'S_box'#the kind of objective function is S_box
                
            if 'and' in line[0]:
                self.kind_objective = 'and'#the kind of objective function is and

        if self.block_cipher[0][1] == 'differential':
            self.delete_operation = 'threeFork'#vectors in threefork operations must be converted to one vector, and this operation must be deleted
            self.dual_operations = 'xor'#using one operation instead of 'xor' or 'threefork'
        elif self.block_cipher[0][1] == 'linear':
            self.delete_operation = 'xor'#vectors in xor operations must be converted to one vector, and this operation must be deleted
            self.dual_operations = 'threeFork'#using one operation instead of 'xor' or 'threefork'

        self.rotaion_is_correct = True #is used in "checkRotation" function to checking that rotations are defined in appropriate place
        self.input_must_be_changed = False #is altered to "True" in "findInputOutputVectors" function, if the input are needed to be rivised
            
        self.organizeRotations()
        self.organizePermutation()
        if self.comprehensive_analysis:
            self.organizeDifferentialLinear()
        self.findForkedVectorsDetails() # inserting the results on self.forked_vectors
        self.importVectorsDetails()
        self.replaceVectorsIndices()
        self.doingPermutation()
        self.checkRotation()
        if self.rotaion_is_correct:
            self.doingRotation()
            
            self.allocateDummyObjectiveVariables()
            
            if self.status == 'gurobi_equations':
                self.constraints = [] #the list which we want to put constraints of all rounds in it
                self.constraints_of_each_round = [] #the list which we want to put constraints of each round seperately in it
                self.produceConstraints()
                self.produceVariables()
                self.constructGurobiEquations()

            elif self.status == 'Cplex_equations':
                self.constraints = [] #the list which we want to put constraints of all rounds in it
                self.constraints_of_each_round = [] #the list which we want to put constraints of each round seperately in it
                self.produceConstraints()
                self.constructCplexEquations()
                
            elif self.status == 'analyze_model':
                self.constraints = [] #the list which we want to put constraints of all rounds in it
                self.constraints_of_each_round = [] #the list which we want to put constraints of each round seperately in it
                self.produceConstraints()
                self.produceVariables()
                self.analyzeModelWithGurobi()
                
            elif self.status == 'variables_char':
                self.representVariablesChar()
                
            elif self.status == 'impossible_trails':
                self.constraints = [] #the list which we want to put constraints of all rounds in it
                self.constraints_of_each_round = [] #the list which we want to put constraints of each round seperately in it
                self.produceConstraints()
                self.produceVariables()
                self.findImpossibleTrails()
            
            elif self.status == 'log_equations':
                self.constraints = [] #the list which we want to put constraints of all rounds in it
                self.constraints_of_each_round = [] #the list which we want to put constraints of each round seperately in it
                self.produceConstraints()
                self.constructLogEquations()
            
        
       
#======================================operation functions ===================================================

    #this function rotates the X, b words to the left
    def rotl(self, X, b):
        #returns the size of block size:
        h = len(X)
        assert b >= 1
        temp = [None]*h
        for i in range(h-b) :
            temp[i] = X[i+b]
        for i in range(h-b,h) :
            temp[i] = X[i-h+b]
        return temp
    
    #this function rotates the X, b words to the right
    def rotr(self, X, b):
        #returns the size of block size:
        h = len(X)
        assert b >= 1
        temp = [None]*h
        for i in range(b) :
            temp[i] = X[h-b+i]
        for i in range(b,h) :
            temp[i] = X[i-b]
        return temp
    
    #this function takes three vectors and their binary vector and...
    #-> gives their three_fork constraint   
    def xorORthreeForkConstraints(self, p0, p1, p2, d) :
        #returns the size of block size:
        h = len(p0)
        constraints = list([])
        for i in range(h) :
            
                constraints = constraints + [d[i]+' - '+p0[i]+' >= 0']
                constraints = constraints + [d[i]+' - '+p1[i]+' >= 0']
                constraints = constraints + [d[i]+' - '+p2[i]+' >= 0']
                constraints = constraints + [p0[i]+' + '+p1[i]+' + '+p2[i]+ ' <= 2']
                if self.status == 'Cplex_equations':
                    constraints = constraints + [p0[i]+' + '+p1[i]+' + '+p2[i]+' - 2 * '+d[i]+ ' >= 0' ]
                else:
                    constraints = constraints + [p0[i]+' + '+p1[i]+' + '+p2[i]+' - 2 '+d[i]+ ' >= 0' ]
                
             
        return constraints
    
    
    #this function takes three vectors and ...
    #-> gives their AND S_box constraint, po, p1 are input & p2 is output 
    def AND(self, p0, p1, p2, s):
        h = len(p0)
        constraints = list([])
        
        for i in range(h):
            if self.status == 'Cplex_equations':
                constraints = constraints + [p2[i] +' == '+ s[i]]
            else:
                constraints = constraints + [p2[i] +'-'+ s[i]+ ' = 0']
        
        for i in range(h) :
            a = [p0[i],p1[i],p2[i]]
            constraints = constraints + [a[2]+' - '+a[0]+' >= 0']
            constraints = constraints + [a[2]+' - '+a[1]+' >= 0']
        
        return constraints    
 
    
    #this function takes three vectors and their binary objective vector and ...
    #-> gives their modular_addition constraint, po, p1 are input & p2 is output 
    def differentialModularAdditionConstraints(self, p0, p1, p2, s, ss) :
        #returns the size of block size:
        h = len(p0)
        constraints = list([])
        for i in range(h-1) :
        
            b = [p0[i],p1[i],p2[i]]#according to the related paper, the first element is input
            a = [p0[i+1],p1[i+1],p2[i+1]]
            constraints = constraints + [a[1]+' - '+a[2]+' + '+s[i]+' >= 0 ']
            constraints = constraints + [a[0]+' - '+a[1]+' + '+s[i]+' >= 0 ']
            constraints = constraints + [a[2]+' - '+a[0]+' + '+s[i]+' >= 0 ']
            constraints = constraints + [a[0]+' + '+a[1]+' + '+a[2]+' + '+s[i]+' <= 3 ']
            constraints = constraints + [a[0]+' + '+a[1]+' + '+a[2]+' - '+s[i]+' >= 0 ']
            constraints = constraints + [b[0]+' + '+b[1]+' + '+b[2]+' + '+s[i]+' - '+a[1]+' >= 0 ']
            constraints = constraints + [a[1]+' + '+b[0]+' - '+b[1]+' + '+b[2]+' + '+s[i]+' >= 0 ']
            constraints = constraints + [a[1]+' - '+b[0]+' + '+b[1]+' + '+b[2]+' + '+s[i]+' >= 0 ']
            constraints = constraints + [a[0]+' + '+b[0]+' + '+b[1]+' - '+b[2]+' + '+s[i]+' >= 0 ']
            constraints = constraints + [a[2]+' - '+b[0]+' - '+b[1]+' - '+b[2]+' + '+s[i]+' >= -2 ']
            constraints = constraints + [b[0]+' - '+a[1]+' - '+b[1]+' - '+b[2]+' + '+s[i]+' >= -2 ']
            constraints = constraints + [b[1]+' - '+a[1]+' - '+b[0]+' - '+b[2]+' + '+s[i]+' >= -2 ']
            constraints = constraints + [b[2]+' - '+a[1]+' - '+b[0]+' - '+b[1]+' + '+s[i]+' >= -2 ']
    
        #ss is asigned to the below equations
        #according to the related paper, the las member of p_i is...
        #-> equivalent to least member
        constraints = constraints + [p0[h-1]+' + '+p1[h-1]+' + '+p2[h-1]+' <= 2 ']
        if self.status == 'Cplex_equations':
            constraints = constraints + [p0[h-1]+' + '+p1[h-1]+' + '+p2[h-1]+' - 2 * '+ss+' >= 0 ']
        else:
            constraints = constraints + [p0[h-1]+' + '+p1[h-1]+' + '+p2[h-1]+' - 2 '+ss+' >= 0 ']
        constraints = constraints + [ss+' - '+p0[h-1]+' >= 0 ']
        constraints = constraints + [ss+' - '+p1[h-1]+' >= 0 ']
        constraints = constraints + [ss+' - '+p2[h-1]+' >= 0 ']  
          
        return constraints
 
    
    #this function takes three vectors and their binary objective vector and ...
    #-> gives their modular_addition constraint, po, p1 are input & p2 is output  
    def linearModularAdditionConstraints(self, p0, p1, p2, s) :
        #returns the size of block size:
        h = len(p0)
        constraints = list([])
        if self.status == 'Cplex_equations':
            constraints = constraints + [s[0]+' == 0']
        else:
            constraints = constraints + [s[0]+' = 0']
              
        for i in range(h) :
        
            #a = [p2[i],p0[i],p1[i]]#according to the related paper, the first element is output
            a = [p0[i],p1[i],p2[i]]
            constraints = constraints + [s[i]+' - '+a[0]+' - '+a[1]+' + '+a[2]+' + '+s[i+1]+' >= 0']
            constraints = constraints + [s[i]+' + '+a[0]+' + '+a[1]+' - '+a[2]+' - '+s[i+1]+' >= 0']
            constraints = constraints + [s[i]+' + '+a[0]+' - '+a[1]+' - '+a[2]+' + '+s[i+1]+' >= 0']
            constraints = constraints + [s[i]+' - '+a[0]+' + '+a[1]+' - '+a[2]+' + '+s[i+1]+' >= 0']
            constraints = constraints + [s[i]+' + '+a[0]+' - '+a[1]+' + '+a[2]+' - '+s[i+1]+' >= 0']
            constraints = constraints + [s[i]+' - '+a[0]+' + '+a[1]+' + '+a[2]+' - '+s[i+1]+' >= 0']
            constraints = constraints + [a[0]+' - '+s[i]+' + '+a[1]+' + '+a[2]+' + '+s[i+1]+' >= 0']
            constraints = constraints + [s[i]+' + '+a[0]+' + '+a[1]+' + '+a[2]+' + '+s[i+1]+' <= 4']
            
        return constraints
    

    #this function takes size, input,output, and objective vector of the S-box and ...
    #-> gives equations related to the S-box  
    def SBox(self, kind, p0, p1, s) :
        
        h = len(s) #returns the number of S-boxes
        
    
        constraints = list([])
        
        
        if kind == 000: # the first S-box  
            print('this is not defined yet')
        
        else:
            
            size_s = int(kind) #the integer size of S_box
            size = kind #the string size of S_box
            for i in range(h):
    
                constraints = constraints + [p0[i*size_s]+' - '+s[i]+' <= 0']
                
                a_condition = p0[i*size_s]
                b_condition = p1[i*size_s]
                e_condition = p0[i*size_s]
                
                if self.status == 'Cplex_equations':
                    c_condition = size+' * '+ p0[i*size_s]
                    d_condition = size+' * '+ p1[i*size_s]
                else:
                    c_condition = size+' '+ p0[i*size_s]
                    d_condition = size+' '+ p1[i*size_s]            
                
                for j in range(size_s-1):
                    
                    constraints = constraints + [p0[j+1 + i*size_s]+' - '+s[i]+' <= 0']
                
                    if self.status == 'Cplex_equations':            
                        c_condition += ' + ' + size +' * '+ p0[j+1 + i*size_s]
                        d_condition += ' + ' + size +' * '+ p1[j+1 + i*size_s]
                    else:
                        c_condition += ' + ' + size +' '+ p0[j+1 + i*size_s]
                        d_condition += ' + ' + size +' '+ p1[j+1 + i*size_s]
                    
                    e_condition += ' + ' + p0[j+1 + i*size_s]
                    
                    if self.status == 'Cplex_equations':
                        a_condition += ' + ' + p0[j+1 + i*size_s]
                        b_condition += ' + ' + p1[j+1 + i*size_s]
                        
                    else:
                        a_condition += ' - ' + p0[j+1 + i*size_s]
                        b_condition += ' - ' + p1[j+1 + i*size_s]
                     
                aa_condition = e_condition+' - '+s[i]+' >= 0'
                
                constraints = constraints + [aa_condition]
    
                if self.status == 'Cplex_equations':
                    cc_condition = c_condition+' - ('+b_condition
                    ccc_condition = cc_condition+') >= 0'
                    
                    dd_condition = d_condition+' - ('+a_condition
                    ddd_condition = dd_condition+') >= 0'
                else:
                    cc_condition = c_condition+' - '+b_condition
                    ccc_condition = cc_condition+' >= 0'
                    
                    dd_condition = d_condition+' - '+a_condition
                    ddd_condition = dd_condition+' >= 0'
                    
                constraints = constraints + [ccc_condition]
                constraints = constraints + [ddd_condition]
    
        return constraints

        
    #this function takes indice of permutation, and the vector and ...
    #-> gives equations related to the S-box  
    def PBox(self, indice, p0):
        h = len(p0)
        temp = [None]*h

        for i in range(h):
            temp[i] = p0[int(self.permutations[indice][i])]

        return temp
            
                
                         
#========================================end of operation functions=================================================================
    #this function inserts rotations in self.rotations
    def organizeRotations(self):

        l = len(self.block_cipher)
        
        #impoting input branches in input_branches
        input_branches = []
        for i in range(len(self.block_cipher[1])//2):
            input_branches.append(self.block_cipher[1][2*i])

        for line in self.block_cipher[2:l-1]:
            #constructing the self.rotations with empty variable
            if line[0] == 'rotr' or line[0] == 'rotl' :
                self.rotations.append(['', ''])
            #===============finding equivelent branches if self.comprehensive_analysis===================
            if self.comprehensive_analysis:
                if line[0] == self.delete_operation:
                    #checking to find a equivalent branch match in previous equivalent branches:
                    delete_operation_exists = True
                    no_continue = False
                    for i in range(3):
                        if no_continue:
                            break
                        for line2 in self.equivalent_branches:
                            if line[2*i+1] in line2:
                                line2.append(line[(2*i+3)%6])
                                line2.append(line[(2*i+5)%6])
                                delete_operation_exists = False
                                no_continue = True
                                break

                    if delete_operation_exists:
                        self.equivalent_branches.append([line[1], line[3], line[5]])
            #===============end of finding equivelen branches if self.comprehensive_analysis=============

       
        #==============organize rotation if self.comprehensive_analysis=========================================================================
        #:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
        if self.comprehensive_analysis:

            #====appending other inputs to input_branches========================
            l_line1 = len(input_branches)
            for line1 in input_branches[0:l_line1]:
                for line2 in self.equivalent_branches:
                    if line1 in line2:
                        for i in range(len(line2)):
                            if line2[i] != line1:
                                input_branches.append(line2[i])
            #====end of appending other inputs to input_branches=================             
            count = 2
            rotations_indice = 0#this indice is allocated to self.rotations
            for line1 in self.block_cipher[2:l-1]:
                if line1[0] == 'rotr' or line1[0] == 'rotl' :
                    self.rotations[rotations_indice][0] = line1
                    
                    #========organize rotation on input branches======================================================================
                    if line1[2] in input_branches:
                        doesnt_need_to_continue = 0#avoind to extra search for find the match for input branch(line2)
                        for line2 in self.block_cipher[count+1:l-1]:

                            #===========if after the rotation exists a delete operation======================       
                            if ( line2[0] == self.delete_operation ):
                                if(line1[2] == line2[1] or line1[2] == line2[3] or line1[2] == line2[5] ):
                                 
                                    
                                    self.rotations.append(['', ''])
                                    self.rotations[rotations_indice+1][0] = line1
                                    impose_rotation_on_branches = []
                                    for k in range(3):
                                        if line2[2*k+1] != line1[2]:
                                            impose_rotation_on_branches.append(line2[2*k+1])

                                    for m in range(2):
                                        no_continue = 0#avoind to extra search for find the match for input branch(line3)
                                        for line3 in self.block_cipher[2:l-1]:

                                            if no_continue == 1:
                                                break
                                 
                                            if ( line3[0] != self.delete_operation and
                                                line3[0] != 'rotr' and line3[0] != 'rotl' ):
                                 
                                                #searching in operands in order to find the match
                                                for n in range(3):
                                                    if impose_rotation_on_branches[m] == line3[2*n+1]:
                                                        self.rotations[rotations_indice][1] = line3
                                                        rotations_indice += 1
                                                        no_continue = 1
                                                        break
        
                                    doesnt_need_to_continue = 1
                            #===========end of if after the rotation exists a delete operation=================

                            #===========if after the rotaion doesn't exists a delete operation=================
                            elif ( line2[0] != self.delete_operation and
                                   line2[0] != 'rotr' and line2[0] != 'rotl' and line2[0] != 'P'):

                                #searching in operands inorder to find the match
                                if line2[0] == 'xor' or line2[0] == 'threeFork' or line2[0] == 'modularAdd' or line2[0] == 'and':
                                    for j in range(3):
                                        if line1[2] == line2[2*j+1]:
                                            self.rotations[rotations_indice][1] = line2
                                            rotations_indice += 1

                                            doesnt_need_to_continue = 1
                                            break

                                #searching in input_output of S_boxes inorder to find the match
                                elif line2[0] == 'S':
                                    for j in range(2):
                                        if line1[2] == line2[2*(j+1)]:
                                            self.rotations[rotations_indice][1] = line2
                                            rotations_indice += 1

                                            doesnt_need_to_continue = 1
                                            break
                            #===========end of if after the rotaion doesn't exists a delete operation===========

                            elif doesnt_need_to_continue == 1:
                                break 
                    #========end of organize rotation on input branches===============================================================
                    #*****************************************************************************************************************
                    #========organize rotation on other branches======================================================================
                    else:
                        doesnt_need_to_continue = 0#avoind to extra search for find the match for input branch(line2)
                        for line2 in self.block_cipher[count-1:1:-1]:

                            #===========if before the rotation exists a delete operation======================
                            if line2[0] == self.delete_operation :
                                if line1[2] == line2[1] or line1[2] == line2[3] or line1[2] == line2[5] :
            
                                    self.rotations.append(['', ''])
                                    self.rotations[rotations_indice+1][0] = line1
                                    impose_rotation_on_branches = []
                                    for k in range(3):
                                        if line2[2*k+1] != line1[2]:
                                            impose_rotation_on_branches.append(line2[2*k+1])

                                    for m in range(2):
                                         no_continue = 0#avoind to extra search for find the match for input branch(line3)
                                         for line3 in self.block_cipher[2:l-1]:

                                             if no_continue == 1:
                                                 break
                                     
                                             if ( line3[0] != self.delete_operation and
                                                  line3[0] != 'rotr' and line3[0] != 'rotl' and line3[0] != 'P'):
                                     
                                                 #searching in operands in order to find the match
                                                 if line3[0] == 'xor' or line3[0] == 'threeFork' or line3[0] == 'modularAdd' or line3[0] == 'and' :
                                                     for n in range(3):#---------------------------
                                                         if impose_rotation_on_branches[m] == line3[2*n+1]:
                                                             self.rotations[rotations_indice][1] = line3
                                                             rotations_indice += 1
                                                             no_continue = 1
                                                             break

                                                 #searching in input_output of S_boxes inorder to find the match
                                                 elif line3[0] == 'S':
                                                     for n in range(2):
                                                         if impose_rotation_on_branches[m] == line3[2*(j+1)]:
                                                             self.rotations[rotations_indice][1] = line3
                                                             rotations_indice += 1
                                                             no_continue = 1
                                                             break

                                     
                                    doesnt_need_to_continue = 1
                                #===========end of if before the rotation exists a delete operation=================

                            #===========if before the rotaion doesn't exists a delete operation=================
                            elif ( line2[0] != self.delete_operation and
                                   line2[0] != 'rotr' and line2[0] != 'rotl' and line2[0] != 'P' ):

                                #searching in operands inorder to find the match
                                if line2[0] == 'xor' or line2[0] == 'threeFork' or line2[0] == 'modularAdd' or line2[0] == 'and':
                                    for j in range(3):
                                        if line1[2] == line2[2*j+1]:
                                            self.rotations[rotations_indice][1] = line2
                                            rotations_indice += 1

                                            doesnt_need_to_continue = 1
                                            break

                                #searching in input_output of S_boxes inorder to find the match
                                elif line2[0] == 'S':
                                    for n in range(2):
                                        if line1[2] == line2[2*(j+1)]:
                                            self.rotations[rotations_indice][1] = line2
                                            rotations_indice += 1
                                            
                                            doesnt_need_to_continue = 1
                                            break
                            #===========end of if before the rotaion doesn't exists a delete operation===========

                            elif doesnt_need_to_continue == 1:
                                break 
                    #========end of organize rotation on other branches==============================================================
                count += 1 
        #:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
        #==============end of organize rotation if self.comprehensive_analysis================================================================
                
        #==============organize rotation if  it is not self.comprehensive_analysis============================================================
        #:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
        if self.comprehensive_analysis == False:
            
            count = 2
            rotations_indice = 0
            for line1 in self.block_cipher[2:l-1]:
                if line1[0] == 'rotl' or line1[0] == 'rotr':
                    
                    self.rotations[rotations_indice][0] = line1
                    more_than_one_rotation = 0#this is used when the rotation is imposed on more than one branch
                    
                    #========organize rotation on input branches======================================================================
                    if line1[2] in input_branches:
                        
                        doesnt_need_to_continue = 0
                        count2 = count+1 #is applied in line3  
                        for line2 in self.block_cipher[count+1:l-1]:

                            if doesnt_need_to_continue == 1:
                                break

                            #if there exists other rotation on same branch and these imposed branches are not in one operation, stop!
                            elif line2[0] == 'rotl' or line2[0] == 'rotr':
                                if line2[2] == line1[2]:
                                    for line3 in self.block_cipher[count2-1:count:-1]:
                                        match = 0
                                        #finding the match in operations
                                        if line3[0] == self.dual_operations or line3[0] == 'modularAdd' or line3[0] == 'and':
                                            for j in range(3):
                                                if line3[2*j+1] == line2[2]:
                                                    match += 1

                                        #finding the match in S-box operations
                                        elif line3[0] == 'S':
                                            for j in range(2):
                                                if line3[2*(j+1)] == line2[2]:
                                                    match += 1
                                                    
                                        if match == 1:
                                            doesnt_need_to_continue = 1
                                            break


                            #finding the match in operations     
                            elif line2[0] == self.dual_operations or line2[0] == 'modularAdd' or line2[0] == 'and':
                        
                                #searching in operands in order to find the match
                                for j in range(3):
                                    if line1[2] == line2[2*j+1]:
                                        
                                        if more_than_one_rotation == 1:
                                            self.rotations.append(['', ''])
                                            self.rotations[rotations_indice][0] = line1

                                        self.rotations[rotations_indice][1] = line2
                                        rotations_indice += 1
                                        more_than_one_rotation = 1
                                        break
                                    
                            #finding the match in S_box operations     
                            elif line2[0] == 'S':
                        
                                #searching in input_output of S_boxes in order to find the match
                                for j in range(2):
                                    if line1[2] == line2[2*(j+1)]:
                                        
                                        if more_than_one_rotation == 1:
                                            self.rotations.append(['', ''])
                                            self.rotations[rotations_indice][0] = line1

                                        self.rotations[rotations_indice][1] = line2
                                        rotations_indice += 1
                                        more_than_one_rotation = 1
                                        break
                                    
                            count2 +=1
                    #========end of organize rotation on input branches==================================================================
                    #********************************************************************************************************************               
                    #========organize rotation on other branches=========================================================================
                    else:

                        doesnt_need_to_continue = 0
                        count2 = count-1 #is applied in line3
                        for line2 in self.block_cipher[count-1:1:-1]:

                            if doesnt_need_to_continue == 1:
                                break
                            
                            #if there exists other rotation on same branch and these imposed branches are not in one operation, stop!
                            elif line2[0] == 'rotl' or line2[0] == 'rotr':
                                if line2[2] == line1[2]:
                                    for line3 in self.block_cipher[count2+1:count]:
                                        
                                        #finding the match in operations
                                        if line3[0] == self.dual_operations or line3[0] == 'modularAdd' or line3[0] == 'and':
                                            match = 0
                                            for j in range(3):
                                                if line3[2*j+1] == line2[2]:
                                                    match += 1

                                        #finding the match in S_box operations
                                        elif line3[0] == 'S':
                                            match = 0
                                            for j in range(2):
                                                if line3[2*(j+1)] == line2[2]:
                                                    match += 1
                                                    
                                        if match == 1:
                                            doesnt_need_to_continue = 1
                                            break

                            #finding the match in operations
                            elif line2[0] == self.dual_operations or line2[0] == 'modularAdd' or line2[0] == 'and':
                                
                                #searching in operands inorder to find the match
                                for j in range(3):
                                    if line1[2] == line2[2*j+1]:
                                        
                                        if more_than_one_rotation == 1:
                                            self.rotations.append(['', ''])
                                            self.rotations[rotations_indice][0] = line1

                                        self.rotations[rotations_indice][1] = line2
                                        rotations_indice += 1
                                        more_than_one_rotation = 1
                                        break

                            #finding the match in S_box operations
                            elif line2[0] == 'S':
                                
                                #searching in operands of S_boxes inorder to find the match
                                for j in range(2):
                                    if line1[2] == line2[2*(j+1)]:
                                        
                                        if more_than_one_rotation == 1:
                                            self.rotations.append(['', ''])
                                            self.rotations[rotations_indice][0] = line1

                                        self.rotations[rotations_indice][1] = line2
                                        rotations_indice += 1
                                        more_than_one_rotation = 1
                                        break 
                            count2 -=1        
                    #========organize rotation on other branches======================================================================
                count +=1   
        #:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
        #==============end of organize rotation if  it is not self.comprehensive_analysis=====================================================



    #this function inserts imposed permutations in self.imposed_by_permutation
    def organizePermutation(self):
        l = len(self.block_cipher)
        
        permutation_indice = 0 #for self.imposed_by_permutation
        #constructing the self.imposed_by_permutation with empty variable and inserting the imposing branches by permutation
        count = 2
        for line1 in self.block_cipher[2:l-1]:
            
            if line1[0] == 'P':
                
                #count = counter#for finding the match after the detected permutaion
                
                self.imposed_by_permutation.append(['', ''])
                self.imposed_by_permutation[permutation_indice][0] = line1

                
                more_than_one_permutation = 0#this is used when the permutation is imposed on more than one operation
                match_found = False#when the match is found after the permutation this variable will be changed.
                
                #finding the match after permutation
                for line2 in self.block_cipher[count+1:l-1]:

                    
                    if line2[0] == 'xor' or line2[0] == 'threeFork' or line2[0] == 'modularAdd' or line2[0] == 'and':
                        for i in range(3):
                            if line1[2] == line2[2*i+1]:
                                
                                if more_than_one_permutation == 1:
                                        self.imposed_by_permutation.append(['', ''])
                                        self.imposed_by_permutation[permutation_indice][0] = line1
                                        
                                self.imposed_by_permutation[permutation_indice][1] = line2
                                more_than_one_permutation = 1
                                match_found = True
                                permutation_indice += 1
                                break
                            
                    elif line2[0] == 'S':
                        for i in range(2):
                            if line1[2] == line2[2*(i+1)]:
                                
                                if more_than_one_permutation == 1:
                                        self.imposed_by_permutation.append(['', ''])
                                        self.imposed_by_permutation[permutation_indice][0] = line1
                                        
                                self.imposed_by_permutation[permutation_indice][1] = line2
                                more_than_one_permutation = 1
                                match_found = True
                                permutation_indice += 1
                                break
                            


                #finding the match before permutation if match doesn't find after permutation
                if match_found == False:
                    
                    #the permutation must be imposed inversly on the operations(before the permutation)
                    
                    more_than_one_permutation = 0#this is used when the permutation is imposed on more than one operation
                    
                    for line2 in self.block_cipher[count-1:0:-1]:
                    
                        if line2[0] == 'xor' or line2[0] == 'threeFork' or line2[0] == 'modularAdd' or line2[0] == 'and':
                            for i in range(3):
                                if line1[2] == line2[2*i+1]:
                                    
                                    if more_than_one_permutation == 1:
                                        self.imposed_by_permutation.append(['', ''])
                                        self.imposed_by_permutation[permutation_indice][0] = line1
                                    
                                    self.imposed_by_permutation[permutation_indice][1] = line2
                                    more_than_one_permutation = 1
                                    permutation_indice += 1
                                    break
                            
                        elif line2[0] == 'S':
                            for i in range(2):
                                if line1[2] == line2[2*(i+1)]:

                                    if more_than_one_permutation == 1:
                                        self.imposed_by_permutation.append(['', ''])
                                        self.imposed_by_permutation[permutation_indice][0] = line1
                                        
                                    self.imposed_by_permutation[permutation_indice][1] = line2
                                    more_than_one_permutation = 1
                                    permutation_indice += 1
                                    break
                            

                        
            count += 1



    #this function ditectes the differential or linear cryptanalysis ...
    #-> and organizes the operation based on them 
    #more precisely: eliminates threefork operations for differential analysis...
    #-> and xor operations for linear analysis and also ...
    #-> deletes the equivalent branches in self.branch_indices
    def organizeDifferentialLinear(self):
        size = len(self.block_cipher[1])#finding how much input (and output) we have (half of the self.block_cipher[1] is the number of input )

        l = len(self.block_cipher)
       
        count = 2 #corresponded with the index of line_list()(operations embark from third lines)
        for line in self.block_cipher[2:l-1]: 
        #trying to find the threefork operations if "self.delete_operation"  is 'threeFork' or
        #trying to find the xor operations if "self.delete_operation"  is 'xor'
        #all indices of this operation are converted to the indice of first element 
        
            #converting all elements of this vector to one element(first element) and delete this vector
            if self.block_cipher[count][0] == self.delete_operation:

                #==============deleting the equivalent branches in self.branch_indices===================================================
                count_branches = 0
                l_branches = len(self.branches_indices)
                for i in range(l_branches):
                    
                    if ( self.branches_indices[count_branches][0] == self.block_cipher[count][3] or
                         self.branches_indices[count_branches][0] == self.block_cipher[count][5] ):
                        del self.branches_indices[count_branches]
                        count_branches -= 1
                        l_branches -= 1

                    count_branches += 1
                #==============end of deleting the equivalent branches in self.branch_indices=============================================

                #navigating the input/output vectors, in order to find the match
                for j in range(size//2):
                              
                    #replacing the first element of operation instead of input(if the first elemet of operation is not input)
                    if self.block_cipher[1][2*j] == self.block_cipher[count][3] or self.block_cipher[1][2*j] == self.block_cipher[count][5]:
                        self.block_cipher[1][2*j] = self.block_cipher[count][1]
                     
                    #replacing the first element of operation instead of output(if the first elemet of operation is not output)
                    if self.block_cipher[l-1][2*j] == self.block_cipher[count][3] or self.block_cipher[l-1][2*j] == self.block_cipher[count][5]:
                        self.block_cipher[l-1][2*j] = self.block_cipher[count][1]#replacing the first element instead of other 2 element
                    
        
                    
                #navigating the other operations, in order to find the match        
                count2 = 2
                for line2 in self.block_cipher[2:l-1]:
            
                    if line2 != line:

                        # the operation is rotation or permutation
                        if self.block_cipher[count2][0] == 'rotr' or self.block_cipher[count2][0] == 'rotl' or self.block_cipher[count2][0] == 'P': 
                            if self.block_cipher[count2][2] == self.block_cipher[count][3] or self.block_cipher[count2][2] == self.block_cipher[count][5]:
                                self.block_cipher[count2][2] = self.block_cipher[count][1]

                        #the operation is modular addition or threefork or xor
                        elif self.block_cipher[count2][0] == 'xor' or self.block_cipher[count2][0] == 'threeFork' or self.block_cipher[count2][0] == 'modularAdd' or self.block_cipher[count2][0] == 'and': 
                            for j in range(3): #navigating the inputs and output of operation
                                if self.block_cipher[count2][2*j + 1] == self.block_cipher[count][3] or self.block_cipher[count2][2*j + 1] == self.block_cipher[count][5]:
                                    self.block_cipher[count2][2*j + 1] = self.block_cipher[count][1]#replacing the first element instead of other 2 element

                        #the operation is S_box
                        elif self.block_cipher[count2][0] == 'S': 
                            for j in range(2): #navigating the inputs and output of operation
                                if self.block_cipher[count2][2*(j + 1)] == self.block_cipher[count][3] or self.block_cipher[count2][2*(j + 1)] == self.block_cipher[count][5]:
                                    self.block_cipher[count2][2*(j + 1)] = self.block_cipher[count][1]#replacing the first element instead of other 2 element
                                
                    count2 +=1    
            
                del self.block_cipher[count] #we don't need this vector(operation) any more   
                count -= 1
                l-=1 
                                
            count += 1
        

#==============================================organize indices=============================================================================

    #this function finds forked vectors and puts the details of them in... 
    #-> the self.forked_vector
    def findForkedVectorsDetails(self):
        size = len(self.block_cipher[1])#finding how much input (and output) we have
        l = len(self.block_cipher)
        
        input_output_indicies = []# gives us the indices of inputs and outputs of block cipher
        for i in range(size//2):#appending the inputs
            input_output_indicies.append(self.block_cipher[1][2*i])
        for i in range(size//2):#appending the outputs
            if self.block_cipher[l-1][2*i] not in input_output_indicies:
                input_output_indicies.append(self.block_cipher[l-1][2*i])
    
        for line in self.branches_indices:
            if line[0] not in input_output_indicies:
                self.forked_vectors.append(line[0])
                self.forked_vectors.append(line[1])


    
    #this function finds the input and output vectors and allocate in_i and out_i indices to input and output vectors respectly & 
    #-> replaces input_vectors & output_vectors in self.branches indices &
    #-> finds forked vectors and allocate f_i indices to forked vectors respectly &
    #-> replaces forked_vectors in self.branches_indices &
    #-> replaces forked_vectors in self.key_MOdular_add_diff
    def importVectorsDetails(self):

        size_in_out = len(self.block_cipher[1])//2#finding how much input (and output) we have
        size_fork = len(self.forked_vectors)//2#finding how much forked vector we have
        l = len(self.block_cipher)
    
        #importing inputs and outputs of block cipher in these lists
        input_blockCipher = []
        output_blockCipher = []
    
        #=======replacing input_vectors in self.branches indices=============================    
        for i in range(size_in_out):
            input_blockCipher.append(list( ['in', str(i), self.block_cipher[1][2*i+1]] ))

            for line_branches_indices in self.branches_indices:
                if line_branches_indices[0] == self.block_cipher[1][2*i]:
                    line_branches_indices[1] = list(input_blockCipher[i])
                    break
        #=======end of replacing input_vector in self.branches indices=======================
        
        #=======replacing output_vectors in self.branches indices=============================
        output_indice = 0#this counter is used for the sake of existing input vectors in output vectors
        for i in range(size_in_out):
            
            for line_branches_indices in self.branches_indices:
                if self.block_cipher[l-1][2*i] == line_branches_indices[0]:
                    
                    #the input vector exists in output vector
                    if type(line_branches_indices[1]) == list:
                        output_blockCipher.append(line_branches_indices[1])
                        self.input_must_be_changed = True
                        break
                    
                    #the input vector doesnt exists in output     
                    else:
                        output_blockCipher.append(list( ['out', str(output_indice), self.block_cipher[l-1][2*i+1]] ))
                        line_branches_indices[1] = list( ['out', str(output_indice), self.block_cipher[l-1][2*i+1]] )
                        output_indice += 1
                        break     
        #=======end of replacing output_vectors in self.branches indices======================
        
    
        #importing forked vectors of block cipher in this list
        forked_blockCipher = []
    
        for i in range(size_fork):
            forked_blockCipher.append(list(['f', str(i), self.forked_vectors[2*i+1]]))
            #forked_vector = list(['f', str(i), self.forked_vectors[2*i+1]]) #constructing the forked vectors

            #=======replacing forked_vectors in self.branches indices============
            for line_branches_indices in self.branches_indices:
                if line_branches_indices[0] == self.forked_vectors[2*i]:
                    line_branches_indices[1] = list(forked_blockCipher[i])
                    break
            #=======end of replacing forked_vectors in self.branches indices=====

            #=======replacing forked_vectors in self.key_MOdular_add_diff========
            if self.key_MOdular_add_diff:
                for j in range(len(self.key_MOdular_add_diff)):
                    if self.key_MOdular_add_diff[j] == self.forked_vectors[2*i]:
                        self.key_MOdular_add_diff[j] = forked_blockCipher[i]
                        break
            #=======end 0f replacing forked_vectors in self.key_MOdular_add_diff==


        #=========================importing details of each branch instead of its size in self.block_cipher========================================
        count = 2 #corresponded with the index of line_list 
        for line in self.block_cipher[2:l-1]:
            
            if self.block_cipher[count][0] == self.dual_operations or self.block_cipher[count][0] == 'modularAdd' or self.block_cipher[count][0] == 'and':

                #input1
                for i in range(len(self.branches_indices)):
                    if self.block_cipher[count][1] == self.branches_indices[i][0]:
                        self.block_cipher[count][1] = list(self.branches_indices[i][1])
                        del self.block_cipher[count][2]
                        break

                #input2
                for j in range(len(self.branches_indices)):
                    if self.block_cipher[count][2] == self.branches_indices[j][0]:
                        self.block_cipher[count][2] = list(self.branches_indices[j][1])
                        del self.block_cipher[count][3]
                        break

                #output
                for k in range(len(self.branches_indices)):
                    if self.block_cipher[count][3] == self.branches_indices[k][0]:
                        self.block_cipher[count][3] = list(self.branches_indices[k][1])
                        del self.block_cipher[count][4]
                        break


            elif self.block_cipher[count][0] == 'rotl' or self.block_cipher[count][0] == 'rotr' or self.block_cipher[count][0] == 'P':

                for i in range(len(self.branches_indices)):
                    if self.block_cipher[count][2] == self.branches_indices[i][0]:
                        self.block_cipher[count][2] = list(self.branches_indices[i][1])
                        del self.block_cipher[count][3]

                        del self.block_cipher[count]
                        l -= 1
                        count -=1
                        break


            elif self.block_cipher[count][0] == 'S':

                #input
                for i in range(len(self.branches_indices)):
                    if self.block_cipher[count][2] == self.branches_indices[i][0]:
                        self.block_cipher[count][2] = list(self.branches_indices[i][1])
                        del self.block_cipher[count][3]
                        break

                #output
                for j in range(len(self.branches_indices)):
                    if self.block_cipher[count][3] == self.branches_indices[j][0]:
                        self.block_cipher[count][3] = list(self.branches_indices[j][1])
                        del self.block_cipher[count][4]
                        break
                       
                
            count += 1
        #=========================end of importing details of each branch instead of its size in self.block_cipher=============================================
            
        
        self.block_cipher[1] = list(input_blockCipher) 
        self.block_cipher[l-1] = list(output_blockCipher)
        self.block_cipher.append(forked_blockCipher)
        


    #this function replaces a list contained the vectors...
    #-> indices of each vector, instead of their length....
    #-> in self.block_cipher and self.branches_indices 
    def replaceVectorsIndices(self):

        l = len(self.block_cipher)

        #=========================replacing input and output vectors indices========================================================================
        size = len(self.block_cipher[1])#finding the number of inputs (and also output)
    
        #initialing the second line of self.block_cipher(self.block_cipher[1]) and one to last line of self.block_cipher(self.block_cipher[l-2])
        indice_input = 0
        indice_output = 0
        for i in range(size):
            size_input_output_ith = int(self.block_cipher[1][i][2]) #size of i-th input (and corresponded with i-th output) 
        
            input_ith_indices = ['['+str(indice_input+j)+']' for j in range(size_input_output_ith)]
            self.block_cipher[1][i][2] = list(input_ith_indices)
            
            if self.block_cipher[l-2][i][0] == 'out':
                output_ith_indices = ['['+str(indice_output+j)+']' for j in range(size_input_output_ith)]
                self.block_cipher[l-2][i][2] = list(output_ith_indices)
                indice_output += size_input_output_ith

            indice_input += size_input_output_ith
        #finding the input branches in output
        if self.input_must_be_changed:
            for line1 in self.block_cipher[l-2]:
                if line1[0] == 'in':

                    for line2 in self.block_cipher[1]:
                        if line1[1] == line2[1]:
                            line1[2] = line2[2]
                            break

        #===initialing indices of each input-output vector instead of their length in self.branches_indices
        for line in self.branches_indices:
            for i in range(size):
                if line[1][0] == 'in' and line[1][1] == self.block_cipher[1][i][1]:
                    line[1][2] = self.block_cipher[1][i][2]
                    break
                elif line[1][0] == 'out' and line[1][1] == self.block_cipher[l-2][i][1]:
                    line[1][2] = self.block_cipher[l-2][i][2]
                    break
        #===end of initialing indices of each input-output vector instead of their length in self.branches_indices
             
        
        #saving the number of input
        self.block_cipher[0].append(['block_cipher_lenght', indice_input])
                
                
        #initialing the rest of the lines of self.block_cipher, which are contained input or output
        for i in range (size):
            count = 2 #corresponded with the index of a line_list which operations are embarked
            for line in self.block_cipher[2:l-2]:
                
                if self.block_cipher[count][0] == self.dual_operations or self.block_cipher[count][0] == 'modularAdd' or self.block_cipher[count][0] == 'and':
                    # searcing on two input and one output for each operation inorder to find the match
                    for j in range (3):
                    
                        if self.block_cipher[count][j+1][0] == 'in' and self.block_cipher[count][j+1][1] == str(i):
                            self.block_cipher[count][j+1][2] = list( self.block_cipher[1][i][2])
                        
                        elif self.block_cipher[count][j+1][0] == 'out':
                            if self.block_cipher[count][j+1][1] == self.block_cipher[l-2][i][1]:
                                self.block_cipher[count][j+1][2] = list( self.block_cipher[l-2][i][2])

                elif self.block_cipher[count][0] == 'S':
                    # searcing on input and output for each S-box operation inorder to find the match
                    for j in range (2):
                    
                        if self.block_cipher[count][j+2][0] == 'in' and self.block_cipher[count][j+2][1] == str(i):
                            self.block_cipher[count][j+2][2] = list( self.block_cipher[1][i][2])
                        
                        elif self.block_cipher[count][j+2][0] == 'out':
                            if self.block_cipher[count][j+2][1] == self.block_cipher[l-2][i][1]:
                                self.block_cipher[count][j+2][2] = list( self.block_cipher[l-2][i][2])
                        
                count +=1
        #=========================end of replacing input and output vectors indices====================================================================

        #=========================replacing forked vectors indices=====================================================================================
        size_fork = len(self.block_cipher[l-1])#finding the number of forked vectors
    
        #initialing the last line of self.block_cipher(self.block_cipher[l-1])
        indice = 0
        for i in range(size_fork):
            size_forked_ith = int(self.block_cipher[l-1][i][2]) #size of i-th forked vector      
            forked_ith_indices = ['['+str(indice+j)+']' for j in range(size_forked_ith)]

            #===initialing indices of each forked vector instead of their length in self.branches_indices
            #forked_ith_indices_for_BI = list( [indice+j for j in range(size_forked_ith)] )
            for line in self.branches_indices:
                if line[1][0] == 'f' and line[1][1] == str(i):                           
                    line[1][2] = forked_ith_indices
            #===end of initialing indices of each forked vector instead of their length in self.branches_indices
        
            self.block_cipher[l-1][i][2] = list(forked_ith_indices)
        
            indice += int(size_forked_ith)
        
        #saving the number of forked_variable
        self.block_cipher[0].append(['forked_number', indice])
        

        #initialing the rest of the lines of self.block_cipher, which are contained forked vectors(self.block_cipher[l-1]) 
        for i in range (size_fork):
            count = 2 #corresponded with the index of a line_list which operations are embarked
            for line in self.block_cipher[2:l-2]:
                
                if self.block_cipher[count][0] == self.dual_operations or self.block_cipher[count][0] == 'modularAdd' or self.block_cipher[count][0] == 'and':
                    # searcing on two input and one output for each operation inorder to find the match
                    for j in range (3):
                    
                        if self.block_cipher[count][j+1][0] == 'f' and self.block_cipher[count][j+1][1] == str(i):
                            self.block_cipher[count][j+1][2] = list( self.block_cipher[l-1][i][2])

                elif self.block_cipher[count][0] == 'S':
                    # searcing on input and output for each operation inorder to find the match
                    for j in range (2):
                    
                        if self.block_cipher[count][j+2][0] == 'f' and self.block_cipher[count][j+2][1] == str(i):
                            self.block_cipher[count][j+2][2] = list( self.block_cipher[l-1][i][2])
                        
                        
                count +=1
        #=========================end of replacing forked vectors indices==============================================================================
       
    
    
#=========================================end of organize indices===========================================================================================     
    #this function operates permutations on block-cipher
    #permutation operates inversely on the branches which are not any operation after permutation
    def doingPermutation(self):

        #trying to operate permutation on self.imposed_by_permutation
        #these changes effect the same changes on self.block_cipher
        for line1 in self.imposed_by_permutation:

            #finding the match
            if line1[1][0] == self.dual_operations or line1[1][0] == 'modularAdd' or line1[1][0] == 'and':
                for i in range(3):       
                    if ( line1[0][2][0] == line1[1][i+1][0] and
                         line1[0][2][1] == line1[1][i+1][1] ):
                        indice = i+1
                        break

            elif line1[1][0] == 'S':
                for i in range(2):
                        
                    if ( line1[0][2][0] == line1[1][i+2][0] and
                         line1[0][2][1] == line1[1][i+2][1] ):
                        indice = i+2
                        break


            #imposing permutation on line1        
            line1[1][indice][2] = self.PBox( line1[0][1], line1[1][indice][2] )



    #this function checks that rotations are defined correctly
    def checkRotation(self):
        for line1 in self.rotations:
            if line1[1] == '' :
                self.rotaion_is_correct = False
                
                #finding the indice of the branch
                for line2 in self.branches_indices:
                    
                    if line1[0][2][0] == line2[1][0]  and line1[0][2][1] == line2[1][1]:
                        branch_indice = line2[0]
                        break

                alarm = 'the statement ( ' + line1[0][0]+ '    ( ' + line1[0][1] + ' )    ' + branch_indice + ' ) is not used in the structure correctly'

                layout = QHBoxLayout(self)
                self.alarm_label = QLabel(alarm, self)
                self.alarm_label.resize(350, 20)
                self.alarm_label.move(60, 10)
                self.warning_label = QLabel(self)
                self.warning_label.setPixmap(QPixmap('warning.png'))
                self.warning_label.move(10, 10)
                
                layout.addWidget(self.alarm_label)
                layout.addWidget(self.warning_label)
                self.setGeometry(500, 200, 450, 50)
                self.setWindowTitle("warning")

                return


    #this function operates rotations on block-cipher
    #rotation operates on the inputs forwardly and operate on other branches backwardly
    def doingRotation(self):
        
        #trying to operate rotation on self.rotations
        #these changes effect the same changes on self.block_cipher
        count = 0
        for line1 in self.rotations:

            #checking that the branch is used in a operation more than one time (in dual operation or modular add)
            branch_in_one_operation = 1#for checking that in a operation exists a branch more than one time
            for line2 in self.rotations[0:count]:
                if ( line2[0][2] == line1[0][2] and
                     line2[1] == line1[1] ):

                    branch_in_one_operation = 2
                    break

            #trying to find a match in line1, and if the branch is used 2 times in operation...
            #->the indice must be secend match
            if line1[1][0] == self.dual_operations or line1[1][0] == 'modularAdd' or line1[1][0] == 'and':
                for i in range(3):
                        
                    if ( line1[0][2][0] == line1[1][i+1][0] and
                         line1[0][2][1] == line1[1][i+1][1] ):

                        if branch_in_one_operation == 1:
                            indice = i+1
                            break
                        if branch_in_one_operation == 2:
                            indice = i+1

            elif line1[1][0] == 'S':
                for i in range(2):
                        
                    if ( line1[0][2][0] == line1[1][i+2][0] and
                         line1[0][2][1] == line1[1][i+2][1] ):
                        indice = i+2
                        break
                        

            #imposing rotation on line1
            if line1[0][2][0] == 'in':
                
                if line1[0][0] == 'rotl':
                    line1[1][indice][2] = self.rotl( line1[1][indice][2], int(line1[0][1]) )
                elif line1[0][0] == 'rotr':
                    line1[1][indice][2] = self.rotr( line1[1][indice][2], int(line1[0][1]) )

            else: #'out' or 'f'
                            
                if line1[0][0] == 'rotl':
                    line1[1][indice][2] = self.rotr( line1[1][indice][2], int(line1[0][1]) )
                elif line1[0][0] == 'rotr':
                    line1[1][indice][2] = self.rotl( line1[1][indice][2], int(line1[0][1]) )

            count += 1
            
  
    #this function defines dummy variables and objective variales ...
    #-> related to the each dual, modular addition, S-box operation...
    #-> respectively and allocates them to the each demanded operation list
    def allocateDummyObjectiveVariables(self):

        
        l = len(self.block_cipher)
    
        #lists contained all dummy and objective vectors details
        dummy_vector_list = []
        objective_vector_list = []
        dummy_diff_modularAdd_list = []#this list is used for least significance inputs and output of differential modular Addition 
    
        #related to the number of needed dummy vector, objective vector & ...
        #->least significance inputs and output of differential modular Addition
        dummy_counter = 0
        objective_counter = 0#this variable is also equivalent to "dummy_diff_modularAdd_indice"
    
        #related to begening indice of each dummy vector and objective vector &...
        #->least significance inputs and output of differential modular Addition
        dummy_indice = 0
        objective_indice = 0
    
        #related to the size of each dummy vector or objective vector 
        dummy_size = 0
        objective_size = 0
    
        count = 2 
        for line in self.block_cipher[2:l-2]:
            

            if self.block_cipher[count][0] == self.dual_operations:
            
                dummy_size = len(self.block_cipher[count][1][2])
            
                dummy_ith_indices_list = ['['+str(dummy_indice+j)+']' for j in range(dummy_size)]
            
                dummy_vector = list(['d', str(dummy_counter), dummy_ith_indices_list]) #constructing the dummy vectors

                #=========appending to the self.dummy_vector================================================================
                #DV == dummy vector
                dummy_ith_indices_for_DV = list( [ 'd', str(dummy_counter), [dummy_indice+j for j in range(dummy_size)] ] )
                self.dummy_vectors.append(dummy_ith_indices_for_DV)
                #=========end of appending to the self.dummy_vector=========================================================
                
                dummy_vector_list.append(dummy_vector)
                self.block_cipher[count].append(dummy_vector)
                dummy_counter +=1
                dummy_indice += dummy_size
            
               
            elif self.block_cipher[count][0] == 'modularAdd':
                #the least significance memebers in differential cryptanalysis are not coperated in these equations 
                if self.block_cipher[0][1] == 'differential':
                    objective_size = len(self.block_cipher[count][1][2]) - 1
                #linear cryptanalysis needs one more element 
                else:
                    objective_size = len(self.block_cipher[count][1][2]) + 1
            
                #constructing the indices of objective vector (& dummy differential addition for differential cryptanalysis)
                objective_ith_indices_list = ['['+str(objective_indice+j)+']' for j in range(objective_size)]

                #constructing the objective vector (& dummy differential addition for differential cryptanalysis)
                objective_vector = list(['s', str(objective_counter), objective_ith_indices_list])
                if self.block_cipher[0][1] == 'differential':
                    dummy_diff_modularAdd_vector = list( ['ss', str(objective_counter), '['+ str(objective_counter) +']'] )

                #=========appending to the self.objective_vectors and self.dummy_diff_modularAdd_vector=====================
                #OV == objective vector
                objective_ith_indices_for_OV = list( [ 's', str(objective_counter), [objective_indice+j for j in range(objective_size)] ] )
                self.objective_vectors.append(objective_ith_indices_for_OV)

                if self.block_cipher[0][1] == 'differential':
                    self.dummy_diff_modularAdd_vector.append(list( ['ss', str(objective_counter)] ))
                #=========end of appending to the self.objective_vectors and self.dummy_diff_modularAdd_vector==============
                                                       
                #inserting all objective_vector in a list(& also dummy_diff_modularAdd_vector in differential cryptanalysis)
                objective_vector_list.append(objective_vector)
                if self.block_cipher[0][1] == 'differential':
                    dummy_diff_modularAdd_list.append(dummy_diff_modularAdd_vector)
                    
                
                self.block_cipher[count].append(objective_vector)
                if self.block_cipher[0][1] == 'differential':
                    self.block_cipher[count].append(dummy_diff_modularAdd_vector)
                    
                objective_counter +=1
                objective_indice += objective_size


            elif self.block_cipher[count][0] == 'and':
                 
                objective_size = len(self.block_cipher[count][1][2]) 
            
                #constructing the indices of objective vector 
                objective_ith_indices_list = ['['+str(objective_indice+j)+']' for j in range(objective_size)]
                #constructing the objective vector 
                objective_vector = list(['s', str(objective_counter), objective_ith_indices_list])

                #=========appending to the self.objective_vectors=========================================================================
                #OV == objective vector
                objective_ith_indices_for_OV = list( [ 's', str(objective_counter), [objective_indice+j for j in range(objective_size)] ] )
                self.objective_vectors.append(objective_ith_indices_for_OV)
                #=========end of appending to the self.objective_vectors and self.dummy_diff_modularAdd_vector==============
                                                       
                #inserting all objective_vector in a list
                objective_vector_list.append(objective_vector)
               
                self.block_cipher[count].append(objective_vector)
                    
                objective_counter +=1
                objective_indice += objective_size
                
                
            elif self.block_cipher[count][0] == 'S':

                objective_size = len(self.block_cipher[count][2][2]) //int(self.block_cipher[count][1])
            
                #constructing the indices of objective vector 
                objective_ith_indices_list = ['['+str(objective_indice+j)+']' for j in range(objective_size)]

                #constructing the objective vector 
                objective_vector = list(['s', str(objective_counter), objective_ith_indices_list])
                
                #=========appending to the self.objective_vectors===========================================================================
                #OV == objective vector
                objective_ith_indices_for_OV = list( [ 's', str(objective_counter), [objective_indice+j for j in range(objective_size)] ] )
                self.objective_vectors.append(objective_ith_indices_for_OV)
                #=========end of appending to the self.objective_vectors and self.dummy_diff_modularAdd_vector==============
                                                       
                #inserting all objective_vector in a list
                objective_vector_list.append(objective_vector)
                    
                self.block_cipher[count].append(objective_vector)
                    
                objective_counter +=1
                objective_indice += objective_size

          
            count +=1
        
        #saving the number of objective_variables
        self.block_cipher[0].append(['objective_number', objective_indice])
        if self.block_cipher[0][1] == 'differential' and self.kind_objective == 'modularAdd':
            self.block_cipher[0].append(['dummy_diff_modularAdd_number', objective_counter])
            
        #saving the number of dummy_variables
        self.block_cipher[0].append(['dummy_number', dummy_indice])
        
        
        self.block_cipher.append(dummy_vector_list)
        self.block_cipher.append(objective_vector_list)
        if self.block_cipher[0][1] == 'differential' and self.kind_objective == 'modularAdd':
            self.block_cipher[-1].append(dummy_diff_modularAdd_list)



    #this function produces the all needed vectors for r-th round...
    #->converts the self.key_MOdular_add_diff members to zero if it's differential analysis
    def constructingRthRoundVectors(self, r):

        l = len(self.block_cipher)

      
        
        #constructing the new self.block_cipher list in size of the old one
        #the main self.block_cipher must not be changed
        block_cipher_rth_round = []
        for i in range(l):
            block_cipher_rth_round.append(list(self.block_cipher[i]))
    
        
        count = 2
        for line in self.block_cipher[2:l-4]:

            #==================if self.block_cipher[count][0] == self.dual_operations or 'modularAdd' or 'and'=======================================================
            if self.block_cipher[count][0] == self.dual_operations or self.block_cipher[count][0] == 'modularAdd' or self.block_cipher[count][0] == 'and':
                #constructing 2 inputs and one output vector variables for each operation in the r-th round
                size_vectors = len(self.block_cipher[count][1][2]) #corresponded with the number of variales in the 'count'-th opearation
            
                for i in range(3):
              
                    if self.block_cipher[count][i+1][0] == 'in':
                        if self.status == 'Cplex_equations':
                            block_cipher_rth_round[count][i+1] = list( ['x['+str(r)+']'+self.block_cipher[count][i+1][2][j] for j in range(size_vectors)] )
                        else:
                            block_cipher_rth_round[count][i+1] = list( ['x'+str(r)+'_'+self.block_cipher[count][i+1][2][j][1:-1] for j in range(size_vectors)] )

                    if self.block_cipher[count][i+1][0] == 'out_1': #for the case of self.input_must_be_changed be True 
                        if self.status == 'Cplex_equations':
                            block_cipher_rth_round[count][i+1] = list( ['x['+str(r-1)+']'+self.block_cipher[count][i+1][2][j] for j in range(size_vectors)] )
                        else:
                            block_cipher_rth_round[count][i+1] = list( ['x'+str(r-1)+'_'+self.block_cipher[count][i+1][2][j][1:-1] for j in range(size_vectors)] )
                            
                    elif self.block_cipher[count][i+1][0] == 'out':
                        if self.status == 'Cplex_equations':
                            block_cipher_rth_round[count][i+1] = list( ['x['+str(r+1)+']'+self.block_cipher[count][i+1][2][j] for j in range(size_vectors)] )            
                        else:
                            block_cipher_rth_round[count][i+1] = list( ['x'+str(r+1)+'_'+self.block_cipher[count][i+1][2][j][1:-1] for j in range(size_vectors)] )
                    
                    elif self.block_cipher[count][i+1][0] == 'f':
                        
                        #checking for self.key_MOdular_add_diff
                        if self.block_cipher[count][i+1] in self.key_MOdular_add_diff:
                            block_cipher_rth_round[count][i+1] = list( ['0'  for j in range(size_vectors)] )
                        else:
                            if self.status == 'Cplex_equations':
                                block_cipher_rth_round[count][i+1] = list( ['f['+str(r)+']'+self.block_cipher[count][i+1][2][j] for j in range(size_vectors)] )
                            else:
                                block_cipher_rth_round[count][i+1] = list( ['f'+str(r)+'_'+self.block_cipher[count][i+1][2][j][1:-1] for j in range(size_vectors)] )
                 
                 
                #=================constructing dummy and objective vectors variables for r-th round=============================================================
                if self.block_cipher[count][0] == self.dual_operations:
                    if self.status == 'Cplex_equations':
                        block_cipher_rth_round[count][4] = list( ['d['+str(r)+']'+self.block_cipher[count][4][2][j] for j in range(size_vectors)] )
                    else:
                        block_cipher_rth_round[count][4] = list( ['d'+str(r)+'_'+self.block_cipher[count][4][2][j][1:-1] for j in range(size_vectors)] )
            
                
                elif self.block_cipher[count][0] == 'and':
                    if self.status == 'Cplex_equations':
                        block_cipher_rth_round[count][4] = list( ['s['+str(r)+']'+self.block_cipher[count][4][2][j] for j in range(size_vectors)] )
                    else:
                        block_cipher_rth_round[count][4] = list( ['s'+str(r)+'_'+self.block_cipher[count][4][2][j][1:-1] for j in range(size_vectors)] )
                        
                        
                #self.block_cipher[count][0] == 'modularAdd' :        
                else:
                    if self.block_cipher[0][1] == 'differential':
                        if self.status == 'Cplex_equations':
                            block_cipher_rth_round[count][4] = list( ['s['+str(r)+']'+self.block_cipher[count][4][2][j] for j in range(size_vectors - 1)] )
                            block_cipher_rth_round[count][5] = 'ss['+str(r)+']'+self.block_cipher[count][5][2]             
                        else:
                            block_cipher_rth_round[count][4] = list( ['s'+str(r)+'_'+self.block_cipher[count][4][2][j][1:-1] for j in range(size_vectors - 1)] )
                            block_cipher_rth_round[count][5] = 'ss'+str(r)+'_'+self.block_cipher[count][5][2][1:-1]
                        
                    #linear cryptanalysis needs one more element 
                    else:
                        if self.status == 'Cplex_equations':
                            block_cipher_rth_round[count][4] = list( ['s['+str(r)+']'+self.block_cipher[count][4][2][j] for j in range(size_vectors + 1)] )
                        else:
                            block_cipher_rth_round[count][4] = list( ['s'+str(r)+'_'+self.block_cipher[count][4][2][j][1:-1] for j in range(size_vectors + 1)] )
                #=================end of constructing dummy and objective vectors variables for r-th round=======================================================
                    
            #==================end of if self.block_cipher[count][0] == self.dual_operations or 'modularAdd' or 'and'=====================================================

            #==================if self.block_cipher[count][0] == 'S'=============================================================================================
            elif self.block_cipher[count][0] == 'S':
                #constructing input and output vector variables for each operation in the r-th round
                size_vectors = len(self.block_cipher[count][2][2]) #corresponded with the number of variales in the 'count'-th opearation
            
                for i in range(2):
                
                    if self.block_cipher[count][i+2][0] == 'in':
                        if self.status == 'Cplex_equations':
                            block_cipher_rth_round[count][i+2] = list( ['x['+str(r)+']'+self.block_cipher[count][i+2][2][j] for j in range(size_vectors)] )
                        else:
                            block_cipher_rth_round[count][i+2] = list( ['x'+str(r)+'_'+self.block_cipher[count][i+2][2][j][1:-1] for j in range(size_vectors)] )

                    if self.block_cipher[count][i+2][0] == 'out_1': #for the case of self.input_must_be_changed be True
                        if self.status == 'Cplex_equations':
                            block_cipher_rth_round[count][i+2] = list( ['x['+str(r-1)+']'+self.block_cipher[count][i+2][2][j] for j in range(size_vectors)] )
                        else:
                            block_cipher_rth_round[count][i+2] = list( ['x'+str(r-1)+'_'+self.block_cipher[count][i+2][2][j][1:-1] for j in range(size_vectors)] )
                        
                    
                    elif self.block_cipher[count][i+2][0] == 'out':
                        if self.status == 'Cplex_equations':
                            block_cipher_rth_round[count][i+2] = list( ['x['+str(r+1)+']'+self.block_cipher[count][i+2][2][j] for j in range(size_vectors)] )
                        else:
                            block_cipher_rth_round[count][i+2] = list( ['x'+str(r+1)+'_'+self.block_cipher[count][i+2][2][j][1:-1] for j in range(size_vectors)] )
                    
                    elif self.block_cipher[count][i+2][0] == 'f':
                        if self.status == 'Cplex_equations':
                            block_cipher_rth_round[count][i+2] = list( ['f['+str(r)+']'+self.block_cipher[count][i+2][2][j] for j in range(size_vectors)] )
                        else:
                            block_cipher_rth_round[count][i+2] = list( ['f'+str(r)+'_'+self.block_cipher[count][i+2][2][j][1:-1] for j in range(size_vectors)] )
                 

                #constructing dummy and objective vectors variables for r-th round
                if self.status == 'Cplex_equations':
                    block_cipher_rth_round[count][4] = list( ['s['+str(r)+']'+self.block_cipher[count][4][2][j] for j in range( len(self.block_cipher[count][4][2]) )] )
                else:
                    block_cipher_rth_round[count][4] = list( ['s'+str(r)+'_'+self.block_cipher[count][4][2][j][1:-1] for j in range( len(self.block_cipher[count][4][2]) )] )
            #==================end of if self.block_cipher[count][0] == 'S'========================================================================================
            count += 1

        return block_cipher_rth_round


    #this function is applied in changeInputOutput and is exploited when the rotation is imposed on old vector
    def imposingRotation(self, old, new, old_imposed):
        size = len(old)
        #rotation_indices = []
        new_imposed  = []
        for i in range(size):
            for j in range(size):
                if old_imposed[i] == old[j]:
                    #rotation_indices.append(j)
                    indice = j
                    break
            new_imposed.append(new[indice])
        return new_imposed

        
                                
    #this function changes the input vectors in self.block_cipher if "self.input_must_be_changed" be True
    def changeInputOutput(self, r):
        l = len(self.block_cipher)
        size = len(self.block_cipher[1])#finding how much input (and output) we have
        
        #=======================changing the inputs and outputs for the second round(r == 1)===================================
        if r == 1:
            change_output = False #this variable is used when there is a input branch in output branches 
            for i in range(size):

                #adjusting the input 
                old_input_vector = list(self.block_cipher[1][i]) 
                new_input_vector = list(self.block_cipher[l-4][i])  
                if new_input_vector[0] == 'out':
                    new_input_vector[0] = 'in'
                elif new_input_vector[0] == 'in':
                    new_input_vector[0] = 'out_1'

                self.block_cipher[1][i] = list(new_input_vector)

                #adjusting the output
                if self.block_cipher[l-4][i][0] == 'in':
                    old_output_vector = list(self.block_cipher[l-4][i]) 
                    self.block_cipher[l-4][i][2] = self.block_cipher[l-4][int(self.block_cipher[l-4][i][1])][2]
                    self.block_cipher[l-4][i][1] = self.block_cipher[l-4][int(self.block_cipher[l-4][i][1])][1]
                    new_output_vector = list(self.block_cipher[l-4][i])
                    change_output = True
                    
                    
                #finding the match of "old_input_vector" and changing it to "new_input_vector" in self.block_cipher
                #finding the match of "old_output_vector" and changing it to "new_output_vector" in self.block_cipher
                for j in range(2, l-4):

                    if self.block_cipher[j][0] == self.dual_operations or self.block_cipher[j][0] == 'modularAdd' or self.block_cipher[j][0] == 'and':
                        for k in range(3):
                            
                            if self.block_cipher[j][k+1][0] == old_input_vector[0] and self.block_cipher[j][k+1][1] == old_input_vector[1]:
                               
                                #rotation is imposed on old_input_vector[2]
                                if self.block_cipher[j][k+1][2] != old_input_vector[2]:
                                    main_rot_new_vector = list(new_input_vector[2])#the new_input_vector must returns to its main type if it's supposed to be applied for the next time 
                                    new_input_vector[2] = list(  self.imposingRotation(old_input_vector[2], new_input_vector[2], self.block_cipher[j][k+1][2])  )
                                    self.block_cipher[j][k+1] = list(new_input_vector)
                                    new_input_vector[2] = list(main_rot_new_vector)
                                else:
                                    self.block_cipher[j][k+1] = list(new_input_vector)

                            if change_output:
                                if self.block_cipher[j][k+1][0] == old_output_vector[0] and self.block_cipher[j][k+1][1] == old_output_vector[1]:

                                    #rotation is imposed on old_input_vector[2]
                                    if self.block_cipher[j][k+1][2] != old_output_vector[2]:
                                        main_rot_new_vector = list(new_output_vector[2])#the new_output_vector must returns to its main type if it's supposed to be applied for the next time 
                                        new_output_vector[2] = list(  self.imposingRotation(old_output_vector[2], new_output_vector[2], self.block_cipher[j][k+1][2])  )
                                        self.block_cipher[j][k+1] = list(new_output_vector)
                                        new_output_vector[2] = list(main_rot_new_vector)
                                    else:
                                        self.block_cipher[j][k+1] = list(new_output_vector)


                    if self.block_cipher[j][0] == 'S':
                        for k in range(2):
                            
                            if self.block_cipher[j][k+2][0] == old_input_vector[0] and self.block_cipher[j][k+2][1] == old_input_vector[1]:
                               
                                #rotation is imposed on old_input_vector[2]
                                if self.block_cipher[j][k+2][2] != old_input_vector[2]:
                                    main_rot_new_vector = list(new_input_vector[2])#the new_input_vector must returns to its main type if it's supposed to be applied for the next time 
                                    new_input_vector[2] = list(  self.imposingRotation(old_input_vector[2], new_input_vector[2], self.block_cipher[j][k+2][2])  )
                                    self.block_cipher[j][k+2] = list(new_input_vector)
                                    new_input_vector[2] = list(main_rot_new_vector)
                                else:
                                    self.block_cipher[j][k+2] = list(new_input_vector)

                            if change_output:
                                if self.block_cipher[j][k+2][0] == old_output_vector[0] and self.block_cipher[j][k+2][1] == old_output_vector[1]:

                                    #rotation is imposed on old_input_vector[2]
                                    if self.block_cipher[j][k+2][2] != old_output_vector[2]:
                                        main_rot_new_vector = list(new_output_vector[2])#the new_output_vector must returns to its main type if it's supposed to be applied for the next time 
                                        new_output_vector[2] = list(  self.imposingRotation(old_output_vector[2], new_output_vector[2], self.block_cipher[j][k+2][2])  )
                                        self.block_cipher[j][k+2] = list(new_output_vector)
                                        new_output_vector[2] = list(main_rot_new_vector)
                                    else:
                                        self.block_cipher[j][k+2] = list(new_output_vector)

                                
                change_output = False
                
                #self.output_variables = list(self.block_cipher[-4])#the self.output_variables needs to be changed
        #=======================end of changing the inputs and outputs for the second round============================
                
        #=======================changing the inputs for the third round (r == 2 to next)==============================
        if r == 2:
            for i in range(size):

                old_input_vector = []

                #adjusting the input
                if self.block_cipher[1][i][0] == 'out_1':
                    
                    #just the indices must be changed into the corespondent output
                    old_input_vector = list(self.block_cipher[1][i])
                    self.block_cipher[1][i][1] = list(self.block_cipher[l-4][i][1])
                    self.block_cipher[1][i][2] = list(self.block_cipher[l-4][i][2])

                    #finding the match of "old_input_vector" and changing the indices in self.block_cipher
                    for j in range(2, l-4):

                        
                        if self.block_cipher[j][0] == self.dual_operations or self.block_cipher[j][0] == 'modularAdd' or self.block_cipher[j][0] == 'and':
                            for k in range(3):

                                if self.block_cipher[j][k+1][0] == old_input_vector[0] and self.block_cipher[j][k+1][1] == old_input_vector[1]:
                               
                                    self.block_cipher[j][k+1][1] = list(self.block_cipher[l-4][i][1])
                                    
                                    #rotation is imposed on old_input_vector[2]
                                    if self.block_cipher[j][k+1][2] != old_input_vector[2]:
                                        main_rot_new_vector = list(self.block_cipher[l-4][i][2])#the new_input_vector must returns to its main type if it's supposed to be applied for the next time 
                                        new_input_vector = list(  self.imposingRotation(old_input_vector[2], self.block_cipher[l-4][i][2], self.block_cipher[j][k+1][2])  )
                                        self.block_cipher[j][k+1][2] = list(new_input_vector)
                                        new_input_vector = list(main_rot_new_vector)
                                    else:
                                        self.block_cipher[j][k+1][2] = list(self.block_cipher[l-4][i][2])


                        if self.block_cipher[j][0] == 'S':
                            for k in range(2):

                                if self.block_cipher[j][k+2][0] == old_input_vector[0] and self.block_cipher[j][k+2][1] == old_input_vector[1]:
                               
                                    self.block_cipher[j][k+2][1] = list(self.block_cipher[l-4][i][1])
                                    
                                    #rotation is imposed on old_input_vector[2]
                                    if self.block_cipher[j][k+2][2] != old_input_vector[2]:
                                        main_rot_new_vector = list(self.block_cipher[l-4][i][2])#the new_input_vector must returns to its main type if it's supposed to be applied for the next time 
                                        new_input_vector = list(  self.imposingRotation(old_input_vector[2], self.block_cipher[l-4][i][2], self.block_cipher[j][k+2][2])  )
                                        self.block_cipher[j][k+2][2] = list(new_input_vector)
                                        new_input_vector = list(main_rot_new_vector)
                                    else:
                                        self.block_cipher[j][k+2][2] = list(self.block_cipher[l-4][i][2])
        #=======================end of changing the inputs for the third round (second to next)=======================
                        
        

    #this function produces all constraints and puts them in self.constraints
    def produceConstraints(self):
        
        main = [] # rth round vectors for each operation
        
        
    
        l = len(self.block_cipher)
    
        for r in range(int(self.block_cipher[0][0])):
            
            constraints_of_round = []#constraints of rth round

            if self.input_must_be_changed:
                
                if r == 1 or r == 2:
                    self.changeInputOutput(r)
                    
        
            main = list( self.constructingRthRoundVectors(r) )#constructing r-th round vectors
            self.block_cipher_all_round.append(main[2:-4])
            
            #adding all input output variables to self.input_output_variables
            self.input_output_variables.append(main[-4])
                
            #starts for constructing the r-th round constraints
            count = 2
            for line in main[2:l-4]:
                
                if main[count][0] == self.dual_operations:
                    self.constraints += self.xorORthreeForkConstraints(main[count][1], main[count][2], main[count][3], main[count][4])
                    constraints_of_round += self.xorORthreeForkConstraints(main[count][1], main[count][2], main[count][3], main[count][4])
            
                elif main[count][0] == 'and':
                    self.constraints += self.AND(main[count][1], main[count][2], main[count][3], main[count][4])
                    constraints_of_round += self.AND(main[count][1], main[count][2], main[count][3], main[count][4])
                    
                elif main[count][0] == 'modularAdd':
                    #modular adition constraint for differential analysis
                    if self.block_cipher[0][1] == 'differential':
                        self.constraints += self.differentialModularAdditionConstraints(main[count][1], main[count][2], main[count][3], main[count][4], main[count][5])
                        constraints_of_round += self.differentialModularAdditionConstraints(main[count][1], main[count][2], main[count][3], main[count][4], main[count][5])
                    #modular adition constraint for linear analysis
                    elif self.block_cipher[0][1] == 'linear':
                        self.constraints += self.linearModularAdditionConstraints(main[count][1], main[count][2], main[count][3], main[count][4])
                        constraints_of_round += self.linearModularAdditionConstraints(main[count][1], main[count][2], main[count][3], main[count][4])

                elif main[count][0] == 'S':
                    self.constraints += self.SBox(main[count][1], main[count][2], main[count][3], main[count][4])
                    constraints_of_round += self.SBox(main[count][1], main[count][2], main[count][3], main[count][4])
  
                count +=1
                
            self.constraints_of_each_round.append(constraints_of_round)
            constraints_of_round = []


    #this fuction produce all the variables and some constraints and put them in self.all_variables
    def produceVariables(self):
        
        r = int(self.block_cipher[0][0])
        
        
        #constructing objective variables
        objective_variables = []
        for i in range(r):
            for j in range(self.block_cipher[0][4][1]):
                objective_variables.append('s'+str(i)+'_'+str(j))
                
        self.all_variables.append(objective_variables)
       
                
        #constructing plaintext variables
        input_variables = []
        for i in range(self.block_cipher[0][2][1]):
            input_variables.append('x0_'+str(i))
            
        self.all_variables.append(input_variables)
    
        #constructing ciphertext variables
        output_variables = []
        for i in range(len(self.input_output_variables[-1])): # i is related to number of branches
            for j in range(len(self.input_output_variables[-1][i][2])): #j is related to size of each branch
                
                if self.input_output_variables[-1][i][0] == 'in':
                    output_variables.append( 'x'+str(r-1)+'_'+self.input_output_variables[-1][i][2][j][1:-1] )
                    
                elif self.input_output_variables[-1][i][0] == 'out':
                    output_variables.append( 'x'+str(r)+'_'+self.input_output_variables[-1][i][2][j][1:-1] )
                    
        
        self.all_variables.append(output_variables)
        
        
        #for i in range( len(self.input_output_variables) ):# i is related to number of rounds  
        main_all_variables = []#this list is contained all variables of each round(except plaintext and ciphertext)
        all_variables = []
        #===========constructing all variables and adding them to self.all_variables[3]=============  
        for i in range(r):
            
            #constructing the all input-output variables of each round(the input of each round is output of the previous round)
            in_out = []
            for j in range( len(self.input_output_variables[i]) ):#j is related to number of branches
                for k in range( len(self.input_output_variables[i][j][2]) ):#k is related to size of each branch
                        
                    if self.input_output_variables[i][j][0] == 'in':
                        in_out.append( 'x'+str(i)+'_'+self.input_output_variables[i][j][2][k][1:-1] )
                    elif self.input_output_variables[i][j][0] == 'out':
                        in_out.append( 'x'+str(i+1)+'_'+self.input_output_variables[i][j][2][k][1:-1] )
            all_variables.append(in_out)
           
            #constructing the all forked branches variables of each round
            f = []
            for j in range(self.block_cipher[0][3][1]):
                f.append('f'+str(i)+'_'+str(j))
            all_variables.append(f)
            
            #constructing the all odjective variables of each round
            s = []
            for j in range(self.block_cipher[0][4][1]):
                s.append('s'+str(i)+'_'+str(j))
            all_variables.append(s)
                
            #constructing the all dummy and ss variables of each round
            d = []
            ss = []
            if len(self.block_cipher[0]) == 7:        
                for j in range(self.block_cipher[0][5][1]):
                    ss.append('ss'+str(i)+'_'+str(j))
                all_variables.append(ss)
                
                for j in range(self.block_cipher[0][6][1]):
                    d.append('d'+str(i)+'_'+str(j))
                all_variables.append(d)
                
                main_all_variables.append(all_variables)
                all_variables = []
                    
            elif len(self.block_cipher[0]) == 6:
                for j in range(self.block_cipher[0][5][1]):
                    d.append('d'+str(i)+'_'+str(j))
                all_variables.append(d)
                    
                main_all_variables.append(all_variables)
                all_variables = []     
        #===========end of constructing all variables and adding them to self.all_variables[3]=============
        self.all_variables.append(main_all_variables)
        #self.all_variables[0] = objective variables
        #self.all_variables[1] = plain text variables
        #self.all_variables[2] = cipher text variables
        #self.all_variables[3] = all variables except plaintext and ciphertext
            
        
 #============================================functions related to execute buttons=========================================       
        
    #this function constructs the constraints based on Gurobi format..
    #-> and puts them in a lp file called "self.constraint_text" 
    def constructGurobiEquations(self):
    
        filename = 'Gurobi-model-'+str(self.block_cipher[0][1])+'-analysis-of-'+str(self.block_cipher[0][0])+'-rounds.lp'
        #filename = 'coins.lp'
        o=open(filename,'w')
        o.write('Minimize')
        o.write('\n')  
        
        #defining objective function
        o.write(self.all_variables[0][0])
        for line in self.all_variables[0][1:]:
            o.write(' + '+line)
            
        o.write('\n')
        o.write('\n')
        o.write('Subject To')
        o.write('\n')
        
        #defining a constraint(plain tex must not be zero)
        o.write(self.all_variables[1][0])
        for line in self.all_variables[1][1:]:
            o.write(' + '+line)
        o.write(' >= 1')
        
        o.write('\n')
        for i in self.constraints:
            o.write(i)
            o.write('\n')
        o.write('\n')
        o.write('\n')
        o.write('Binary')
        o.write('\n')
        
        #========printing all the variables in the lp file===============   
        for i in range(2): #printing the plaintext and ciphertext variables
            for j in range(len(self.all_variables[1])):
                o.write(self.all_variables[i+1][j] +'\n')
        
        #printing the rest of the variables
        for line1 in self.all_variables[3]:
            for line2 in line1:
                for line3 in line2:
                    o.write(line3 +'\n')
        #========end of printing all the variables in the lp file======
        o.close()
        
        self.constraints = []
        
     
        
    #this function constructs the constraints based on CPLEX format..
    #-> and puts them in a text file called "self.constraint_text" 
    def constructCplexEquations(self):
        #self.setGeometry(350,190, 700, 400)
        self.setFixedSize(700, 400)
        self.setWindowTitle("CPLEX مدل سازگار با فرمت ")
        self.constraint_text = QTextBrowser(self)
        self.constraint_text.setGeometry(0,0, 700, 400)
      
        self.constraint_text.append('int rounds_number = '+str(self.block_cipher[0][0])+';')
        self.constraint_text.append('int block_cipher_lenght = '+str(self.block_cipher[0][2][1])+';')
        self.constraint_text.append('int forked_number = '+str(self.block_cipher[0][3][1])+';')
        self.constraint_text.append('int objective_number = '+str(self.block_cipher[0][4][1])+';')
        if self.kind_objective == 'modularAdd' and self.block_cipher[0][1] == 'differential':
            self.constraint_text.append('int dummy_diff_modularAdd_number = '+str(self.block_cipher[0][5][1])+';')
            self.constraint_text.append('int dummy_number = '+str(self.block_cipher[0][6][1])+';')
        else:
            self.constraint_text.append('int dummy_number = '+str(self.block_cipher[0][5][1])+';')
        self.constraint_text.append('\n')        
        self.constraint_text.append('range i = 0..rounds_number;')
        self.constraint_text.append('range j = 0..rounds_number-1;')
        self.constraint_text.append('range k = 0..block_cipher_lenght-1;')
        self.constraint_text.append('range l = 0..forked_number-1;')
        self.constraint_text.append('range m = 0..objective_number-1;')
        if self.kind_objective == 'modularAdd' and self.block_cipher[0][1] == 'differential':
            self.constraint_text.append('range n = 0..dummy_diff_modularAdd_number-1;')
        self.constraint_text.append('range o = 0..dummy_number-1;')
        self.constraint_text.append('\n')        
        self.constraint_text.append('dvar boolean x [i][k];')
        self.constraint_text.append('dvar boolean f [j][l];')
        self.constraint_text.append('dvar boolean s [j][m];')
        if self.kind_objective == 'modularAdd' and self.block_cipher[0][1] == 'differential':
            self.constraint_text.append('dvar boolean ss[j][n];')
        self.constraint_text.append('dvar boolean d [j][o];')
        self.constraint_text.append('dvar int total_round[j];')
        self.constraint_text.append('dvar int total;')
        self.constraint_text.append('\n')                
        self.constraint_text.append('minimize')
        self.constraint_text.append('sum (a in j) sum(b in m) s[a,b];\n')   
        self.constraint_text.append('subject to  {')                      
        self.constraint_text.append('sum (a in k) x[0,a]>=1;')
        for i in self.constraints:
            self.constraint_text.append(i+';')
        self.constraint_text.append('\n')
        for i in range(int(self.block_cipher[0][0])):
           self.constraint_text.append('total_round['+str(i)+'] == sum (a in m) s['+str(i)+',a];')
        self.constraint_text.append('\n\ntotal == sum (a in j) total_round[a];')
        self.constraint_text.append('}')
        self.constraints = []
        
        
        
    #this function builds the MILP model compatible with Groubi...
    #-> and opitomizes it
    def analyzeModelWithGurobi(self):
           
        #==============constructing the MILP model=============================
        filename = 'Gurobi-model.lp'
        o=open(filename,'w')
        o.write('Minimize')
        o.write('\n')  
        
        #defining objective function
        o.write(self.all_variables[0][0])
        for line in self.all_variables[0][1:]:
            o.write(' + '+line)
            
        o.write('\n')
        o.write('\n')
        o.write('Subject To')
        o.write('\n')
        
        #defining a constraint(plain tex must not be zero)
        o.write(self.all_variables[1][0])
        for line in self.all_variables[1][1:]:
            o.write(' + '+line)
        o.write(' >= 1')
        
        o.write('\n')
        for i in self.constraints:
            o.write(i)
            o.write('\n')
        o.write('\n')
        o.write('\n')
        o.write('Binary')
        o.write('\n')
        o.write('\n')
        
        #========printing all the variables in the lp file===============   
        for i in range(2): #printing the plaintext and ciphertext variables
            for j in range(len(self.all_variables[1])):
                o.write(self.all_variables[i+1][j] +'\n')
        
        #printing the rest of the variables
        for line1 in self.all_variables[3]:
            for line2 in line1:
                for line3 in line2:
                    o.write(line3 +'\n')
        #========end of printing all the variables in the lp file======
        
        o.write('End')
        o.close()
        #==============end of constructing the MILP model======================
        #f = StringIO()
        #self.oldstdout = sys.stdout
        #sys.stdout = StringIO()

        self.m = read('Gurobi-model.lp')           
        #self.m.Params.LogFile='optimize-model.log'  
        self.m.optimize()
        #self.log_text.append(sys.stdout.getvalue() )        
        #Replace stdout if needed
        #sys.stdout = self.oldstdout
        
        global vars_char
        vars_char = []
         
        var_char = ['','']
        for v in self.m.getVars():
                #print(v.varName, v.x)
            var_char[0] = v.varName
            var_char[1] = v.x
            vars_char.append(var_char)
            var_char = ['','']
        self.constraints = []
        
        
    
    #this function represents the amount of obtained variable   
    def representVariablesChar(self):
                
        #self.setGeometry(350,190, 700, 400)
        self.setFixedSize(700, 400)
        self.setWindowTitle("نمایش مقدار متغیرههای تعریف شده")
        self.represent_variables_char = QTextBrowser(self)
        self.represent_variables_char.setGeometry(0,0, 700, 400)
        
        self.represent_variables_char.append('the amount of defined variables are as follows:')
        self.represent_variables_char.append('\n')
        
        for line in vars_char:
            self.represent_variables_char.append('        '+str(line[0])+'  =  '+str(line[1]))
            self.represent_variables_char.append('\n')
            
        

    #this function finds impossible trails(zeor correlations or impossible differentials)
    def findImpossibleTrails(self):
        
        self.find_impossible_trails = findImpossibleTrails(self.all_variables, self.constraints_of_each_round)
        self.find_impossible_trails.show()
        
        #self.setGeometry(600,240, 400, 400)
        #self.setWindowTitle("ورودی و خروجی های ناممکن به دست آمده")
        #self.log_text = QTextBrowser(self)
        #self.log_text.setGeometry(0,0, 400, 400)
        
        #==============constructing the MILP model=============================
        filename = 'impossible-trails-model.lp'
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
        
        #defining a constraint(cipher tex must be equal to one)
        o.write(self.all_variables[2][0])
        for line in self.all_variables[2][1:]:
            o.write(' + '+line)
        o.write(' = 1')
        
        o.write('\n')
        o.write('condition1')
        o.write('\n')
        o.write('condition2')
        
        o.write('\n')
        for i in self.constraints:
            o.write(i)
            o.write('\n')
        o.write('\n')
        o.write('\n')
        o.write('Binary')
        o.write('\n')
        o.write('\n')
        
        #========printing all the variables in the lp file===============   
        for i in range(2): #printing the plaintext and ciphertext variables
            for j in range(len(self.all_variables[1])):
                o.write(self.all_variables[i+1][j] +'\n')
        
        #printing the rest of the variables
        for line1 in self.all_variables[3]:
            for line2 in line1:
                for line3 in line2:
                    o.write(line3 +'\n')
        #========end of printing all the variables in the lp file======
        
        o.write('End')
        o.close()
        #==============end of constructing the MILP model======================
  
    

    #this function constructs the details  based on CPLEX format..
    #-> and puts them in a text file called " self.log_text" 
    def constructLogEquations(self):
        #self.setGeometry(400,240, 800, 400)
        self.setFixedSize(800, 400)
        self.setWindowTitle("comprehensive report for the produced inequaliies")
        self.log_text = QTextBrowser(self)
        self.log_text.setGeometry(0,0, 800, 400)
        font = QFont()
        font.setPointSize(10)
        self.log_text.setFont(font)

        self.log_text.append('These MILP equation are for "'+ str(self.block_cipher[0][0]) + '" rounds of "'+ self.block_cipher[0][1]
            + '" cryptanalisis of a bit-oriented structure with lenght "'+str(self.block_cipher[0][2][1])+' bits".\n' )

        #===========appending equivalent branches in to self.log_text========================================
        if self.equivalent_branches != []:
            self.log_text.append('The below branches are equivaleted to each other'+
                ' and are converted to one branch:')
    
            for line in self.equivalent_branches:

                text = line[0]
                for i in range(len(line)-1):
                    text += '"   &   "'+line[i+1]
                    
                self.log_text.append( '        The branches  "'+text+
                '"   are equivalent, and are converted in to   "'+ line[0]+'"' )
        #===========end of appending equivalent branches in to self.log_text=================================

        #===========describing the members of each branch(indice)============================================
        self.log_text.append('\nThe members of each branch For round "ith" (without concidering'+
                ' rotation or permutation) is described as fallows:')
        
        for line1 in self.branches_indices:
            
            if line1[1][0] == 'in':
                status = 'x[i][j'+line1[1][1]+'],     '
                line1.append('x[i][j'+line1[1][1]+']')
            elif line1[1][0] == 'out':
                status = 'x[i+1][j'+line1[1][1]+'], '
                line1.append('x[i+1][j'+line1[1][1]+']')
            elif line1[1][0] == 'f':
                status = 'f[i][k'+line1[1][1]+'],     '
                line1.append('f[i][k'+line1[1][1]+']')

            #===appending symbolic state of each rotation to self.rotations===========
            for line2 in self.rotations:
               
                if ( line1[1][0] == line2[0][2][0] and line1[1][1] == line2[0][2][1] ):
                     
                    if line2[0][2][0] == 'in':
                        if line2[0][0] == 'rotr':
                            line2.append( '(>>'+line2[0][1]+') ' )
                            line2.append(line1[-1])
                        elif line2[0][0] == 'rotl':
                            line2.append( '(<<'+line2[0][1]+') ' )
                            line2.append(line1[-1])

                    else:
                        if line2[0][0] == 'rotr':
                            line2.append( '(<<'+line2[0][1]+') ' )
                            line2.append(line1[-1])
                        elif line2[0][0] == 'rotl':
                            line2.append( '(>>'+line2[0][1]+') ' )
                            line2.append(line1[-1])
            #===end of appending symbolic state of each rotation to self.rotations===

            #===appending symbolic state of each permutation to self.imposed_by_permutation===========
            for line2 in self.imposed_by_permutation:
               
                if ( line1[1][0] == line2[0][2][0] and line1[1][1] == line2[0][2][1] ):
                     
                    line2.append( 'P'+str(line2[0][1]+1)+' ' )
                    line2.append(line1[-1])
            #===end of appending symbolic state of each permutation to self.imposed_by_permutation===

            #=========adding the described members to the self.log_text===============
            append_text = ''
            for j in range( len(line1[1][2])-1 ):
                append_text = append_text + str(line1[1][2][j][1:-1]) + ', '
            append_text = append_text + str( line1[1][2][-1][1:-1])
            
                
            if line1[1][0] == 'f':
                self.log_text.append(  '        The indice  "'+ line1[0]+
                        '"   -->   '+status+'   k'+line1[1][1]+' = '+ append_text   )
            else:
                self.log_text.append(  '        The indice  "'+ line1[0]+
                        '"   -->   '+status+'   j'+line1[1][1]+' = '+ append_text   )
            #=========end of adding the described members to the self.log_text=========
        #===========end of describing the members of each branch(indice)=====================================

        #==========describing the dummy members which are defined============================================
        self.log_text.append('\nThe dummy vectors in round "ith" which are used in'+
                ' each "' +self.dual_operations+ '" operation are described as fallows:')

        for line in self.dummy_vectors:

            line.append('d[i][l'+line[1]+']')
            append_text = ''
            for j in range( len(line[2])-1 ):
                append_text = append_text + str(line[2][j]) + ', '
            append_text = append_text + str( line[2][-1] )

            self.log_text.append(  '        The dummy vector, number  "'+ line[1]+
                    '"   -->   d[i][l'+line[1]+'],   l'+line[1]+' = '+ append_text   )
        #==========end of describing the dummy members which are defined======================================

        #==========describing the objective members which are defined=========================================
        self.log_text.append('\nThe objective vectors in round "ith" which are used in'+
                ' each '+self.kind_objective+' operation are described as fallows:')

        for line in self.objective_vectors:

            line.append('s[i][m'+line[1]+']')

            append_text = ''
            for j in range( len(line[2])-1 ):
                append_text = append_text + str(line[2][j]) + ', '
            append_text = append_text + str( line[2][-1] )

            self.log_text.append(  '        The objective vector, number  "'+ line[1]+
                    '"   -->   s[i][m'+line[1]+'],   m'+line[1]+' = '+ append_text   )

        #importing self.dummy_diff_modularAdd_vector in case of differential cryptanalysis 
        if self.block_cipher[0][1] == 'differential':
            for line in self.dummy_diff_modularAdd_vector:
                line.append('ss[i]['+str(line[1])+']')
                self.log_text.append(  '        The objective dummy member, number  "'+ str(line[1])+
                    '"   -->   ss[i]['+str(line[1])+']'  )
        #==========end of describing the objective members which are defined====================================
#############
        #==========describing inputs and output of the operations with their dummy or objective vectors=========
        self.log_text.append('\nThe inputs & output of the operations in each round with their'+
                ' objective vector or dummy vector are described as fallows: \n\n')
        
        count = 1
        for line1 in self.block_cipher_all_round:
            self.log_text.append('the description of block cipher for the round '+str(count)+' is: \n\n')
            for line2 in line1:
                
                #===================if the operation is S_box========================================================
                if line2[0] == 'S':
                    append_text = [line2[2][0], line2[3][0], line2[4][0]]
                    for i in range(3):
                        for line3 in line2[i+2][1:]:
                            append_text[i] += ', ' + line3
                    
                    self.log_text.append('S-box ('+line2[1]+' bits '+')        ('+ append_text[0]+
                                         '),        ('+append_text[1]+' ),      objective vector  -->  ('+append_text[2]+' )')
                    self.log_text.append('\n')
                #===================end of if the operation is S_box=================================================
                
                #===================if the operation is not S_box========================================================
                else:
                    append_text = [line2[1][0], line2[2][0], line2[3][0], line2[4][0]]
                    for i in range(4):
                        for line3 in line2[i+1][1:]:
                            append_text[i] += ', ' + line3
                     
                        
                    #three fork or XOR operation
                    if line2[0] == self.dual_operations:
                        self.log_text.append(self.dual_operations + '  ('+ append_text[0]+'),        ('
                                             +append_text[1]+'),        ('+append_text[2]+'),      dummy vector  -->  ('+append_text[3]+' )')
                        self.log_text.append('\n')
                        
                        
                    #modular addition operation
                    if line2[0] == 'modularAdd':
                        
                        if self.block_cipher[0][1] == 'differential':
                            self.log_text.append('modularAdd   ('+ append_text[0]+'),        ('
                                             +append_text[1]+'),        ('+append_text[2]+'),      objective vector  -->  ('
                                             +append_text[3]+' ),      dummy variable  -->  '+line2[5])
                            self.log_text.append('\n')
                            
                        else:          
                            self.log_text.append('modularAdd   ('+ append_text[0]+'),        ('
                                             +append_text[1]+'),        ('+append_text[2]+'),      objective vector  -->  ('+append_text[3]+' )')
                            self.log_text.append('\n')
                    
                    
                    #and operation
                    if line2[0] == 'and':
                        self.log_text.append('and   ('+ append_text[0]+'),        ('
                                             +append_text[1]+'),        ('+append_text[2]+'),      objective vector  -->  ('+append_text[3]+' )')
                        self.log_text.append('\n')
                #===================end of if the operation is not S_box=================================================
                    
            self.log_text.append('************************************************************************************************\n')
            count +=1
 
 #============================================end of functions related to execute buttons=======================================           
                    
 
      
           




