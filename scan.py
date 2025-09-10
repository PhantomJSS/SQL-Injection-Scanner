## The following programmer is an SQL Injection Scanner that retrieves from fields from a given URL to check if they are vulnerable to Injection Attacks
## DISCLAIMER: TO BE USED RESPONSIBLY AND FOR EDUCATIONAL PURPOSES ONLY, THE DEVELOPER IS NOT LIABLE FOR ANY MISUSE OF THE PROGRAM

## Imports the necessary libraries (Requests handles HTTP requests; BeautifulSoup parses HTML to extract forms)
import requests
from bs4 import BeautifulSoup

## Creates a session that keeps headers consistent and prevents the request being flagged as being from a bot
s = requests.Session()
s.headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36"

## Method that downloads the given URL before parsing it to find all form fields
def htmlforms(url):
    soup = BeautifulSoup(s.get(url).content, "html.parser")
    return soup.find_all("form")

## Method that collects the metadata about a form (Action is where the form submits data to, Method is whether it is GET/POST, Inputs is the type of input fields (Name, Type, Value))
def formdetail(form):

    ## Creates an empty dictionary to store all form information before retrieving the action and method from the form
    details = {}
    action = form.attrs.get("action")
    method = form.attrs.get("method", "get")
    inputs = []

    ## Loops through all possilbe input fields and retrieves their values (Type: Type of field, Name: Name of the field, Value: Any default value)
    for inputtag in form.find_all("input"):
        inputtype = inputtag.attrs.get("type", "text")
        inputname = inputtag.attrs.get("name")
        inputvalue = inputtag.attrs.get("value", "")
        inputs.append({"type": inputtype, "name": inputname, "value": inputvalue})
    
    details['action'] = action
    details['method'] = method
    details['inputs'] = inputs
    return details

## Method that looks for common SQL error messages in the server's response
def vulnerable(response):
    errors = {"quoted string not properly terminated", "unclosed quotation mark after the character syntax", "you have an error in your SQL syntax"}

    ## If one of the listed errors is found, the page is vulnerable to SQL Injection Attacks
    for error in errors:
        if error in response.content.decode().lower():
            return True
    return False

## Method that scans the given URL to get all the forms before attempting to inject each field and submitting
def scanner(url):
    forms = htmlforms(url)
    print(f'[+] Detected {len(forms)} forms on {url}') 

    for form in forms:
        details = formdetail(form)

        ## Attempts to inject single and double quotes into thye input fields
        for i in "\"'":
            data = {}
            ## Hidden fields keep original values but are appended with single/double quotes, other fields are filled with "test", submit buttons are skipped
            for inputtag in details["inputs"]:
                if inputtag["type"] == "hidden" or inputtag["value"]:
                    data[inputtag['name']] = inputtag["value"] + i
                elif inputtag["type"] != "submit":
                    data[inputtag['name']] = f"test{i}"

            print(url)
            formdetail(form)

            ## Submits the form using GET/Post
            if details["method"] == "post":
                res = s.post(url, data=data)
            elif details["method"] == "get":
                res = s.get(url, params=data)
            else:
                print('The following URL is invalid and contains no forms')

            ## If the page prints an error message, the page is vulnerable, else, it is safe
            if vulnerable(res):
                print(f'Vulnerable to SQL Injection Attacks @ Link: {url}')
            else:
                print('Not Vulnerable to SQL Injection Attack')
                break

## Runs the program for a specified URL
if __name__ == "__main__":
    url = "https://github.com"
    scanner(url)