from colorama import Fore, Style, init
import time
init(autoreset=True)

banner_ascii = f"""
{Fore.GREEN}
                                                                                                              
                                                                                                              
                                                     ████                                                     
                                                  ████  ████                                                  
                                                ███        ███                                                
                                              ███   ██████   ███                                              
                                             ██   ███    ███   ██                                             
                                           ███  ███        ███  ███                                           
                                          ██   ██            ██   ██                                          
                                          ██  ██     ████     ██  ██                                          
                                         ██  ██      ████      ██  ██                                         
                                         ██  ██       ██       ██  ██                                         
                                         ██  █        ██        █  ██                                         
                        ████████         ██  █        ██        █  ██         ████████                        
                        ██     ████      ██  ██       ██       ██  ██      ████     ██                        
                            ███   ███     ██  ██      ██      ██  ██     ███   ███                            
                            █████   ███   ███   ██    ██    ██   ███   ███   █████                            
                                ███   █████████  ██   ██   ██  █████████   ███                                
                                  ████        ██  ██  ██  ██  ██         ███                                  
                                     ███████████  ██ ████ ██  ███████████                                     
                                            ███  ████████████  ███                                            
                              ███████████████   ████  ██  ████   ███████████████                              
                           ████               ███    ████    ███               ████                           
                                ███████████████   ███    ███   ███████████████                                
                              ██          ███   ███        ███   ███          ███                             
                             ███         ██   ██              ██   ██         ███                             
                                        ██  ███                ███  ██                                        
                                       ███  ██                  ██  ███                                       
                                           ██                    ██                                           
                                           ███                  ███                                          
{Style.RESET_ALL}
                          OCTOPOPS
                     Developed by 0xzulu
"""
# Print line by line slowly
def print_banner_slowly():
    for line in banner_ascii.splitlines():
        print(Fore.GREEN + line + Style.RESET_ALL)
        time.sleep(0.05)  # Adjust speed here (seconds per line)
