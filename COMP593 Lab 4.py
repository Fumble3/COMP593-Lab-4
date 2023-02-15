from sys import argv
import os
import re 
import sys
from Log_analysis import get_log_file_path_from_cmd_line, filter_log_by_regex
import pandas as pd

def main():
    log_file = get_log_file_path_from_cmd_line(1)
    port_traffic = tally_port_traffic(log_file)
    
    for port_num, count in port_traffic.items():
         if count >= 100: 
            generate_port_traffic_report(log_file, port_num)

    pass

# TODO: Step 3
def get_log_file_path_from_cmd_line():
    num_params = len(argv) - 1
    if num_params >= 1:
            log_file_path = sys.argv[1]
            if os.path.isfile(log_file_path):
                return log_file_path
        
            else:
                print("Error: Path is not a file")
                sys.exit(1)
    else:
        print("Error: missing log file path")
        sys.exit(1)
    
# TODO: Steps 4-7
def filter_log_by_regex(log_file, regex, ignore_case=True, print_summary=False, print_records=False):
    """Gets a list of records in a log file that match a specified regex."""
    
    records = []

    regex_flags = re.IGNORCASE if ignore_case else 0

    with open(log_file, 'r') as file:
        #Iterate through file line by line
         for line in file:
        #Check line for regex match
              match = re.search(regex,line, regex_flags)
              if match:
                   records.append(line)

    if print_records is True:
         print(*records, sep='', end='\n')

    if print_summary is True:
         print(f'The log file contains {len(records)} records that case-{"in" if ignore_case else ""}sensitive match the regex "{regex}". ')

    return records

# TODO: Step 8
def tally_port_traffic(log_file):
    data = filter_log_by_regex(log_file, r'DPT=(.+?) ')[1]
    port_traffic = {}
    for d in data:
         port = d[0] 
         port_traffic[port] = port_traffic.get(port, 0) + 1  
    return port_traffic

# TODO: Step 9
def generate_port_traffic_report(log_file, port_number):
    
    regex = r'(.{6}) (.{8}) .*SRC=(.+?) DST=(.+?) .+SPT=(.+) ' + f'DPT=({port_number}) '
    data = filter_log_by_regex(log_file, regex)[1]
     
    report_df = pd.DataFrame(data) 
    header_row = ('Date', 'Time', 'Source IP Address', 'Destination IP Address', 'Source Port', 'Destination Port')
    report_df.to_csv(f'destination_port_{port_number}_report.csv', index=False, header=header_row) 

# TODO: Step 11
def generate_invalid_user_report(log_file):
    return

# TODO: Step 12
def generate_source_ip_log(log_file, ip_address):
    return

if __name__ == '__main__':
    main()