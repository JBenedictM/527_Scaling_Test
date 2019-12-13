import argparse
import os
import subprocess
import numpy as np
import sys

arg_parser = argparse.ArgumentParser()
arg_parser.add_argument("-s", "--signature",
                        help="specify the yara signature to use", required=True)
arg_parser.add_argument("-f", "--files",
                        help="specify the files/folder to scan", required=True)
arg_parser.add_argument("-c", "--run_count",
                        help="specify how many times the program will be run, and averaged",
                        required=True)

# parse args
args = arg_parser.parse_args()
sig_path = args.signature
file_path = args.files
run_count = int(args.run_count)

# run yara with time monitor
yara_cmd = "yara " + sig_path + " " + file_path

term_cmd = "/usr/bin/time -v " + yara_cmd
term_cmd2 = "time " + yara_cmd


max_res_list = []
avg_res_list = []
usr_time_list = []
sys_time_list = []
real_time_list = []
for i in range(run_count):
    
    ps = subprocess.Popen(term_cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    output = ps.communicate()[0].decode("utf-8")

    
    print("Iteration: " + str(i))
    
    print(output)
        
    output_list = output.split("\n")
    #print("first index: " + output_list[0][:6])

    curr_str = output_list[0].lstrip().rstrip()[:7]
    while(output_list[0].lstrip().rstrip()[:7] != "Command"):
        #print("curr str: " + curr_str)
        output_list = output_list[1:]
        
        curr_str = output_list[0].lstrip().rstrip()[:7] 
    
    
    max_res_line = output_list[9]
    avg_res_line = output_list[8]
    usr_time_line = output_list[1]
    sys_time_line = output_list[2]
    real_time_line = output_list[4]
    
    
    print(max_res_line)
    max_res = int(max_res_line.split(":")[-1].rstrip().lstrip())
    max_res_list.append(max_res)
    print(max_res)
    
    print(avg_res_line)
    avg_res = int(avg_res_line.split(":")[-1].rstrip().lstrip())
    avg_res_list.append(avg_res)
    print(avg_res)
    
    
    print(usr_time_line)
    usr_time = float(usr_time_line.split(":")[-1].rstrip().lstrip())
    usr_time_list.append(usr_time)
    print(usr_time)
    
    
    print(sys_time_line)
    sys_time = float(sys_time_line.split(":")[-1].rstrip().lstrip())
    sys_time_list.append(sys_time)

    print(sys_time)
    
    
    print(real_time_line)
    real_time = float(real_time_line.split(":")[-1].rstrip().lstrip())    
    real_time_list.append(real_time)
    print(real_time)
    

# calculate mean and standard deviation
#print(max_res_list)
#avg = int(np.sum(max_res_list, dtype=np.int32)/len(max_res_list))
#print("manual avg: " + str(avg))
#print("average: " + str(np.average(max_res_list)))
#print("std: " + str(np.std(max_res_list, dtype=np.int32)))

max_res_avg = int(np.average(max_res_list))
max_res_std = int(np.std(max_res_list, dtype=np.int32))

avg_res_avg  = int(np.average(avg_res_list))
avg_res_std = int(np.std(avg_res_list, dtype=np.int32))

usr_time_avg = float(np.average(usr_time_list))
usr_time_std = float(np.std(usr_time_list, dtype=np.float32))

sys_time_avg = float(np.average(sys_time_list))
sys_time_std = float(np.std(sys_time_list, dtype=np.float32))

 
real_time_avg = float(np.average(real_time_list))
real_time_std = float(np.std(real_time_list, dtype=np.float32))


print("Average max res: " + str(max_res_avg))
print("Std deviation: +-" + str(max_res_std))

print("Average total size: " + str(avg_res_avg))
print("Std deviation: +-" + str(avg_res_std))

print("Average usr time: " + str(usr_time_avg))
print("Std deviation: +-" + str(usr_time_std))

print("Average sys time: " + str(sys_time_avg))
print("Std deviation: +-" + str(sys_time_std))

print("Average real time: " + str(real_time_avg))
print("Std deviation: +-" + str(real_time_std))


