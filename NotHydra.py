import colored  #-- See: https://pypi.org/project/colored/
from html.parser import HTMLParser
import os
import random
import requests
import sys
import time


#============================================================================================================[ TO DO ]==
# Flesh out true/false login string detection to work by tag, rather than by line
# Incorporate retries into true/false login string detection


#=================================================================================================[ GLOBAL CONSTANTS ]==
VERSION = "0.9.0"
SPLASH = """
          )             )                            
       ( /(        ) ( /(       (                    
       )\())    ( /( )\())(     )\ ) (      )        
      ((_)\  (  )\()|(_)\ )\ ) (()/( )(  ( /(        
       _((_) )\(_))/ _((_|()/(  ((_)|()\ )(_))       
      | \| |((_) |_ | || |)(_)) _| | ((_|(_)_        
 _ _  | .` / _ \  _|| __ | || / _` || '_/ _` |  _ _  
(_|_) |_|\_\___/\__||_||_|\_, \__,_||_| \__,_| (_|_) 
                          |__/                       
{}\n\n""".format("(v{})".format(VERSION).rjust(50))

#-----------------------------------------------------------------------------------------------------------------------
VERIFY = 3

DEFAULT_VERBOSITY = 3   # ( FAIL:0, INFO:1, WARN:2, DEBUG:3 )
DEFAULT_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:76.0) Gecko/20100101 Firefox/76.0"

GET_IP = "http://icanhazip.com/"    #-- others: [ https://ifconfig.me/ip, https://ifconfig.me/all ]
CMD_LN = {
    "-h"        : (None, "Shows this help menu.", None),
    "-H"        : (None, "Shows this help menu with args sorted alphabetically.", None),
    "-badssl"   : (None, "Ignore bad ssl certificates.", None),
    "-getip"    : ([str], "Override for {}".format(GET_IP), "-ip"),
    "-ip"       : (None, "Gets the ip from {} and exits immediately.".format(GET_IP), "-tor"),
    "-tor"      : ([str], "The TOR control ip and port, eg. localhost:9050", "-ip"),
    "-url"      : ([str], "The url containing the login form. (required)", None),
    "-plain"    : (None, "Disables terminal colors for terminals that doesn't support it.", None),
    "-test"     : ([str, str], "A valid user/pass combination to test.", "-verify"),
    "-true"     : ([str], "String in response body if user/password is correct.", "-false", "-verify"),# "-delim"),
    "-false"    : ([str], "String in response body if user/password is wrong.", "-true", "-verify"),# "-delim"),
    "-u"        : ([str], "The user to target.", "-U"),# "-delim"),
    "-U"        : ([str], "A file with a list of users to target.", "-u"),
    "-verify"   : ([int], "Verify result N times.", "-true", "-false"),
    #"-w"        : ([str], "A file with a list of passwords to test.", "-W"),
    #"-W"        : ([str], "A url containing a list of passwords to test.", "-w"),

    #"-len"      : ([int, int], "Min-max length inclusive.", "-c"),
    #"-c"        : ([str], "Characters allowed in the password.", "-len"),
    #"-delim"    : ([str], "Specifies a delimeter to use to separate strings.", None),
    #"-r"        : ([int], "Line number in wordlist to resume at.", "-R"),
    #"-R"        : ([str], "Word in wordlist to resume at.", "-r"),
    #"-ua"       : ([str], "Custom UserAgent string to use.", None),
    #"-cookie"   : ([str], "Custom cookie to use.", None),
    #"-head"     : ([str, str], "Custom HTTP header to send.", None),
    #"-loot"     : ([str], "Filename to dump successful results in.", None),
    #"-threads"  : ([int], "Number of parallel threads.", None),
    #"-retry"    : ([int, int], "The amount of attempts to make if an HTTP error occurs and the number of seconds to wait.", None),

    "-v"        : ([int], "Verbosity: FAIL:0, INFO:1, WARN:2, DEBUG:3", None)
}


#=========================================================================================================[ CLASSES ]==
USE_COLOR = not "-plain" in sys.argv

class Print():
    INDENT_WIDTH = 4
    INDENT_BULLETS = ("*", "+", "-", "")

    VERBOSITY_FAIL = 0
    VERBOSITY_WARN = 1
    VERBOSITY_INFO = 2
    VERBOSITY_DEBUG = 3

    VERBOSITY_VALUES = {
        VERBOSITY_FAIL  : ("FAIL", "#ff0000", "#aa0000"),
        VERBOSITY_INFO  : ("INFO", None, None),
        VERBOSITY_WARN  : ("WARN", "#ffff00", "#999900"),
        VERBOSITY_DEBUG : ("DEBUG", "#0000ff", "#000099"),
    }

    @property
    def verbosity(self) -> int:
        return self._verbosity

    @verbosity.setter
    def verbosity(self, value : int):
        if (value < 0) or (value > self.VERBOSITY_DEBUG):
            #-- Error
            self.fail("Value for verbosity needs to be between 0 and {}".format(self.VERBOSITY_DEBUG))
        else:
            self._verbosity = value
            self.debug(f"Verbosity set to {value}.")

    @property
    def time_since_last_print(self):
        """ Returns the time in seconds since last print. """
        return time.now() - self.last_print_time

    def __init__(self, use_color : bool, output_verbosity : int):
        """ A class for printing in colour at different levels of verbosity. """
        self.last_print_time = time.time()
        self._usecolor = use_color 
        self.verbosity = output_verbosity


    def _output(self, text, indent, level):
        """ Prints messages depending on the verbosity. Also handles message clorization and indentation.
            Returns True if the message was printed to screen or False if the verbosity muted the output.
        """
        
        printed = (level <= self._verbosity)
        if printed:
            #-- Reset timer
            self.last_print_time = time.time()

            #-- Get default values for level
            token, color, low_color = self.VERBOSITY_VALUES[level]

            #-- Prep strings
            t_time = time.strftime("%H:%M:%S", time.localtime())
            t_token = ""
            if indent > 0:
                t_token = self.INDENT_BULLETS[min([len(self.INDENT_BULLETS) - 1, indent - 1])].ljust(2).rjust(self.INDENT_WIDTH * indent)
            else:
                t_token = token.upper().strip()
            t_text = text.strip()
            
            #-- Apply paint
            if self._usecolor and (not color is None):
                t_token = "{}{}{}".format(colored.fg(color), t_token, colored.attr("reset"))
                t_text = "{}{}{}".format(colored.fg(low_color), t_text, colored.attr("reset"))
                t_time = "{}{}{}".format(colored.fg("#888888"), t_time, colored.attr("reset"))
            
            #-- Print product
            # First line
            t_text = t_text.split("\n")
            if indent > 0:
                print("{}{}".format(t_token, t_text[0]))
            else:
                print("[{}] {}: {}".format(t_time, t_token, t_text[0]))

            # Subsequent lines
            if len(t_text) > 1:
                no_token = "".rjust(INDENT_WIDTH * indent) if indent > 0 else "".rjust(4 + len(t_time))
                for i in range(1, len(t_text)):
                    print("{} {}".format(no_token, t_text[i]))

        #-- Result
        return printed

    def debug(self, text : str, indent : int = 0):
        """ Prints a DEBUG message """
        return self._output(text, indent, self.VERBOSITY_DEBUG)

    def warn(self, text : str, indent : int = 0):
        """ Prints a WARN message """
        return self._output(text, indent, self.VERBOSITY_WARN)

    def info(self, text : str, indent : int = 0):
        """ Prints an INFO message """
        return self._output(text, indent, self.VERBOSITY_INFO)

    def fail(self, text : str, indent : int = 0, fatal_error : bool = True):
        """ Prints a FAIL message """
        printed = self._output(text, indent, self.VERBOSITY_FAIL)

        if fatal_error:
            #-- Exit
            print("\n\n")
            exit(0)

        return printed

    def splash(self, splash):
        """ Prints the splash screen """
        if self._usecolor:
            fancy_splash = splash.split("\n")[0:-3]
            fancy_version = "\n".join(splash.split("\n")[-3:])
            i = 0
            for i in range(len(fancy_splash)):
                print("{}{}{}".format(colored.fg("#FF{:02x}00".format(round((200 * i) / (len(fancy_splash) - 1)))), fancy_splash[i], colored.attr("reset")))
            print("{}{}{}".format(colored.fg("blue"), fancy_version, colored.attr("reset")))
        else:
            print(splash)


#-----------------------------------------------------------------------------------------------------------------------
class HtmlForms(HTMLParser):
    """ Extension for the HTMLParser to extract forms automatically.
        ref:  https://docs.python.org/3/library/html.parser.html
    """
    @property
    def forms(self) -> list:
        """ Returns all HTML forms
        """
        return self._forms

    @property
    def password_forms(self) -> list:
        """ Return all forms with a password input
        """
        if self._L is None:
            self._L = list()
            for form in self._forms:
                if not form[0] is False:
                    self._L.append(form)

        return self._L


    def __init__(self, html:str):
        """ Parses html and extracts all html forms
        """
        super().__init__()

        self._L = None
        self._is_in_form = False
        self._forms = list()
        self.feed(html)
        

    def handle_starttag(self, tag, attrs):
        """ Parse opening/standalone tags
            Form list explained:
                [0] password input name
                [1] text input name(s)
                [2] form opening tag
                [3] form tag name=value kvps
                [4] form tag name=type kvps
        """
        if tag == "form":
            self._is_in_form = True
            self._forms.append([False, [], {  k : v for k,v in attrs }, {}, {}])
        elif self._is_in_form and ("name" in [ k  for k, v in attrs ]):
            tag_name = None
            tag_type = None
            tag_value = None
            for k,v in attrs:
                if k == "type":
                    tag_type = v
                elif k  == "name":
                    tag_name = v
                elif k  == "value":
                    tag_value = v

            if (tag_type == "password"):
                self._forms[-1][0] = tag_name
            elif (tag_type == "text"):
                self._forms[-1][1].append(tag_name)
            self._forms[-1][3][tag_name] = tag_value
            self._forms[-1][4][tag_name] = tag_type

        return

    def handle_endtag(self, tag):
        """ Parse closing tags
        """
        if self._is_in_form and (tag == "form"):
            self._is_in_form = False

        return


#-----------------------------------------------------------------------------------------------------------------------
class HtmlStrings(HTMLParser):
    """ Extension for the HTMLParser that just extracts all the strings.
        ref:  https://docs.python.org/3/library/html.parser.html
    """
    #-- Properties
    @property
    def Unique(self) -> set:
        """ Returns all strings as a set """
        return self._set

    @property
    def Strings(self) -> set:
        """ Returns all strings as a list """
        return self._strings


    #-- Class constructor
    def __init__(self, html:str):
        """ Parses html and extracts all strings as a set
        """
        super().__init__()
        self._set = set()
        self._strings = list()
        self.feed(html)


    #-- Methods
    def handle_data(self, data):
        """ Adds data if string is not null or empty. """
        if len(data.strip()) > 0:
            self._set.add(data.strip())
            self._strings.append(data.strip())
            print("Encountered some data  :", data)


#-----------------------------------------------------------------------------------------------------------------------
class FakeBrowser():
    #-- Properties
    # To Do


    #-- Constructor
    def __init__(self, url:str, proxy, ignore_ssl_errors:bool, retry:tuple, tf:tuple, cookies:dict, headers:dict):
        """ X """
        #-- Set default values
        self.url = url
        self.tf = tuple(tf)
        self.proxy = proxy
        self.silent_ssl = ignore_ssl_errors
        self.retry = retry
        self.cookies = dict(cookies)
        self.headers = dict(headers)


    #-- Private Methods
    def reset_session(self):
        """ Starts a new requests session. """
        self.session = requests.session()
        self.session.proxies = self.proxy
        self.session.verify = self.silent_ssl
        self.session.cookies = self.cookies
        self.session.headers = self.headers
        self.form = None
    
    
    def step1_get_form(self):
        """ Starts a new session and gets the login form. """
        result = False
        self.reset_session()
        PRINT.debug("Getting login form...", 1)
        try:
            r = self.session.get(self.url)
            f = HtmlForms(r.text).password_forms
        except e as Exception:
            PRINT.debug("Failed to get the login form:", 1)
            PRINT.debug(f"ERR: {e}", 2)

        if not f is None:
            f = f[0]
            try:
                self.form = list(f)
                self.form_action = requests.compat.urljoin(self.url, f[2]["action"])
                self.form_method = f[2]["method"].lower()
                self.form_input_pass = f"{f[0]}"
                self.form_input_text = list(f[1])
                self.form_data = dict(f[3])
                result = True
                PRINT.debug("Done!", 1)
            except e as Exception:
                self.form = None
                PRINT.debug("Failed to parse the login form:", 1)
                PRINT.debug(f"ERR: {e}", 2)

        return result


    def step2_submit_form(self, username:str, password:str):
        """ Starts a new session and gets the login form. """
        result = False
        PRINT.debug("Submitting form...", 1)
        try:
            r = None
            if self.form_method == "post":
                r = self.session.post(self.form_action, data=self.form_data)
            else:
                r = self.session.get(self.form_action, data=self.form_data)
            result = r.text
            PRINT.debug("Done!", 1)

        except e as Exception:
            PRINT.debug("Failed to submit the login form:", 1)
            PRINT.debug(f"ERR: {e}", 2)

        return result


    #-- Public Methods
    def login(self, username:str, password:str) -> tuple:
        """ Gets the HTML form from a given page
        """
        def retry_wrapper(self, callback, *args, **kwargs):
            """ Wraps a function in a loop that tries until it gets a good result. """
            retries = 0
            result = False
            while (result is False) and (retries < self.retry[0]):
                result = callback(*args, **kwargs)
                if result is False:
                    retries = retries + 1
                    if (retries < self.retry[0]):
                        PRINT.debug(f"Failed attempt {retries} of {self.retry[0]}. Retrying in {self.retry[1]} seconds...", 1)
                        time.sleep(self.retry[1])
                    else:
                        PRINT.warn(f"Failed {self.retry[0]} attempts. Giving up.", 0)

            return result

        result = None
        PRINT.info("Logging in user '{}' with password '{}'...".format(username, "*" * len(password)))
        if self.retry_wrapper(self, self.step1_get_form):
            result = self.retry_wrapper(self, self.step2_submit_form, username, password)

        return result


#-----------------------------------------------------------------------------------------------------------------------
class Commandline():
    #-- Properties
    @property
    def value(self) -> dict:
        """ Returns all parsed command line args as a dictionary. """
        return self._parsed


    #-- Constructor
    def __init__(self, help_arg : str, sorted_help : str, use_color : bool, verbosity : int):
        """ Parses command line args. if the help-arg is supplied, it prints the help menu and exits immediately. """
        #-- Init Output
        self.PRINT = Print(use_color, verbosity)

        #-- Show splash screen
        self.PRINT.splash(SPLASH)
        if (len(sys.argv) == 1) or (help_arg in sys.argv[1:]):
            #-- Show help and exit
            self.help()
        elif (not sorted_help is None) and (sorted_help in sys.argv[1:]):
            #-- Show sorted help and exit
            self.help(sort_keys = True)
        else:
            #-- Parse command line args
            self._parsed = dict()
            unparsed = sys.argv[1:]
            valid_keys = set(CMD_LN.keys())
            while len(unparsed) > 0:
                unparsed, valid_keys = self._chop(unparsed, valid_keys)

            self._keysused = set(self._parsed.keys())


    #-- Private Methods
    def _chop(self, unparsed:list, valid_keys:set):
        """ Parses the next command line argument, populates the parsed values and returns the unprocessed keys and arguments. """
        key = unparsed[0]
        if key in valid_keys:
            #-- Extract the key's values (if applicable)
            length = 0 if CMD_LN[key][0] is None else len(CMD_LN[key][0])
            if (length + 1) > len(unparsed):
                self.help("The argument '{}' expects {} parameters but got {}.".format(key, length, len(unparsed) - 1))
            else:
                values = True if length == 0 else unparsed[1:length + 1]
                if not values is True:
                    self.PRINT.debug("Command line arg -> {}: ['{}']".format(key.rjust(8), "', '".join(values)))
                    for i in range(len(values)):
                        cast = CMD_LN[key][0][i]
                        try:
                            values[i] = cast(values[i])
                        except ValueError:
                            self.help("Arg '{}' expects parameter {} to be <{}> but got '{}'".format(key, i + 1, cast.__name__, values[i]))
                
                self._parsed[key] = values

            #-- Remove the processed bits
            valid_keys.remove(key)
            unparsed = unparsed[length + 1:]
        elif key in set(CMD_LN.keys()):
            #-- Arg already used
            self.help("The arg '{}' has already been used.".format(unparsed[0]))
        else:
            #-- Show help and exit
            self.help("Unknown arg '{}'.".format(unparsed[0]))

        return unparsed, valid_keys


    #-- Public Methods
    def is_set(self, key:str):
        """ Returns true if an arg is present. """
        return key in self._keysused

    def require_one(self, *args:str):
        """ Returns True if at least one of the args are present. """
        i = 0
        result = False
        while (not result) or (i < len(args)):
            result = self.is_set(args[i])
            i = i + 1
        return result

    def require_all(self, *args:str):
        """ Returns True if all of the args are present. """
        i = 0
        result = True
        while result and (i < len(args)):
            result = self.is_set(args[i])
            i = i + 1
        return result

    def get(self, key:str):
        """ Returns a value if it is set, or None if not. """
        result = None 
        if self.is_set(key):
            result = self._parsed[key]
        return result

    def help(self, text=None, sort_keys=False):
        """ Shows help with an error message (if provided). """
        def see_also(entry):
            """ Generates and returns a (see x, y) string. """
            result = ""
            if not entry[2] is None:
                result = "  (also: " + ", ".join(entry[2:]) + ")"
            return result

        def get_syntax(key, entry):
            """ Generates and returns a syntax string. """
            result = key
            if not entry is None:
                result = result + " <{}>".format("> <".join([x.__name__ for x in entry]))
            return result

        #-- Find the longest syntax
        longest_syntax = 0
        for x in CMD_LN.keys():
            syn = get_syntax(x, CMD_LN[x][0])
            if longest_syntax < len(syn):
                longest_syntax = len(syn)

        #-- Print syntax error
        print("NOT_HYDRA HALP:")
        if not text is None:
           print("  ERROR: {}\n".format(text))
        
        #-- Print help menu
        print("  ARGS:")
        show_keys = sorted(CMD_LN.keys()) if sort_keys else CMD_LN.keys()
        for x in show_keys:
            print("    {} : {}{}".format(get_syntax(x, CMD_LN[x][0]).ljust(longest_syntax), CMD_LN[x][1], see_also(CMD_LN[x])))
        print("\n\n")
        exit(0)


#==========================================================================================================[ METHODS ]==
def is_online() -> bool:
    """ Returns True if google is reachable
    """
    result = False
    try:
        r = requests.get('http://www.google.com/')
        result = True
    except requests.exceptions.HTTPError as err:
        result = False

    return result


def print_ips(f_badssl, proxy):
    """ Prints the Clear-net IP ans well as the Proxy-IP if a proxy is provided.
    """
    src = "NET"
    try:
        #-- Fetch clearnet IP
        r = requests.get(GET_IP, verify=f_badssl)
        print("  {} IP: {}".format(src, r.text.strip()))
        if not proxy is None:
            #-- Fetch TOR IP
            src = "TOR"
            r = requests.get(GET_IP, proxies=proxy, verify=f_badssl)
            print("  {} IP: {}".format(src, r.text.strip()))
    except requests.exceptions.RequestException as err:
        PRINT.fail("Trouble getting {} IP from '{}'.".format(src.lower(), GET_IP), fatal_error = False)
        PRINT.fail(str(err), 1)
    print("\n")


def form_get(url : str, proxy, ignore_ssl_errors : bool) -> tuple:
    """ Gets the HTML form from a given page
    """
    result = None

    try:
        r = requests.get(args.get("-url")[0], proxies=proxy, verify=ignore_ssl_errors)
        f = HtmlForms(r.text)
        #PRINT.debug(str(f.password_forms[0]))
        result = f.password_forms

    except:
        result = False

    return result


def form_submit(form : dict, ignore_ssl_errors : bool, proxy : tuple, **kwargs) -> tuple:
    """ Submits an HTML form and retuens the headers, cookies and response body as a tuple(dict, dict, str).
    """
    result = None

    try:
        if form["method"].lower() == "post":
            r = requests.post(form["action"], proxies=proxy, verify=ignore_ssl_errors, data=kwargs)
        else:
            r = requests.get(form["action"], proxies=proxy, verify=ignore_ssl_errors, data=kwargs)

        #f = HtmlForms(r.text)
        #PRINT.debug(str(f.password_forms[0]))
        result = r.text

    except Exception as e:
        result = False

    return result

def do_login(url : str, username : str, password : str, ignore_ssl_errors : bool, proxy : tuple) -> str:
    """ Gets the first HTML form containing a password input, performs a login and returns the resulting HTML. """
    result = None
    PRINT.info(f"Performing login for '{username}' with password '{password}'...")
    
    #-- Get the login form
    PRINT.debug(f"Getting HTML form from '{url[0]}'...", 1)
    form = form_get(url, proxy, ignore_ssl_errors)
    if form is None:
        PRINT.debug("Error getting form.")
    else:
        #-- We got at least one password form
        #-- Find first password form that only has one text input
        frm_valid = []
        frm_captcha = []
        frm_other = []
        frm_id = None
        for i in range(len(form)):
            if len(form[i][1]) == 1:
                #-- Valid login form with two entry fields
                frm_id = "Valid login"
                frm_valid.append(i)
            elif len(form[i][1]) == 2:
                #-- Possible captcha form
                frm_id = "Recaptcha?"
                frm_captcha.append(i)
            else:
                #-- I don't know
                frm_id = "Unknown"
                frm_other.append(i)
            PRINT.debug(f"{frm_id} -> {form[0][2]}", 1)

        if len(frm_valid) >= 1:
            #-- We have a valid login form 
            if len(frm_valid) > 1:
                PRINT.debug("Multiple login forms detected, so using the first one.")

            #-- Resolve the form action
            frm_tag = form[frm_valid[0]][2]
            frm_tag["action"] = requests.compat.urljoin(url[0], frm_tag["action"])

            #-- Fill out the form
            frm_data = dict(form[frm_valid[0]][3])
            frm_data[form[frm_valid[0]][1][0]] = username
            frm_data[form[frm_valid[0]][0]] = password

            #-- Submit the form
            result = form_submit(frm_tag, ignore_ssl_errors, proxy, **frm_data)
        elif len(frm_captcha) >= 1:
            #-- We have a recaptcha
            PRINT.warn("Solving recaptchas automatically is not yet supported.")
        else:
            PRINT.warn("Could not find a valid login form.")

        #PRINT.debug(str(form[0][2]))
        #result = form

    return result

def get_test_data(url : str, test_user : tuple, verify_count : int, ignore_ssl_errors : bool, proxy : tuple) -> list:
    """ If a test-user is provided, return a list containing [[GOOD], [BAD]] login results. """
    def get_bad_pass(valid_pass, tested_passes, length):
        badpass = None
        while (badpass is None) or (badpass == valid_pass)  or (badpass in tested_passes):
            badpass = ""
            for i in range(length):
                badpass = badpass + random.choice("abcdefghijklmnopqrstuvwxyz0123456789")
        return badpass

    result = None

    if not test_user is None:
        #-- Perform test submissions
        result = [[], []]

        #-- Perform test submissions
        bad_passes = list()
        while len(result[0]) < verify_count:
            #-- Do bad login
            bad_passes.append(get_bad_pass(test_user[1], bad_passes))
            result[1].append(do_login(url, test_user[0], bad_passes[-1], ignore_ssl_errors, proxy))

            #-- Do good login
            result[0].append(do_login(url, test_user[0], test_user[1], ignore_ssl_errors, proxy))
    else:
        PRINT.debug("The -test flag has not been set.")

    return result


def get_truefalse(str_true : str, str_false: str, test_tf : list) -> tuple:
    """ Returns the sanitized -true and -false flags and uses test data if it is provided. 
    """
    def is_null_or_empty(value : str) -> bool:
        """ Returns True if value is zero-length string or None. """
        return (value is None) or (len(value) == 0)

    def get_or_autodetect_tf(test_tf):
        """ Returns sets unique to true or false logins. """
        def get_set_intersection(text):
            """ Returns a set of all similar lines in given text lists. """
            result = set([x.strip() for x in text[0].replace("\r", "").split("\n")])
            for i in range(1, len(text)):
                set_test = set([x.strip() for x in text[i].replace("\r", "").split("\n")])
                result = set_test.intersection(result)
            return result
        html_t = get_set_intersection(test_tf[0])
        html_f = get_set_intersection(test_tf[1])

        result = [
            sorted(html_t.difference(html_f)), 
            sorted(html_f.difference(html_t))
        ]
        return result

    def check_subset(value_a, value_b, flag_a, flag_b):
        """ Makes sure value_a is not a substring of value_b """
        result = value_a
        if (not ((value_a is None) or (value_b is None))) and (value_a in value_b):
            PRINT.warn("Arg {0} is a substring of {1}. Arg {0} has been omitted.".format(flag_a, flag_b))
            result = None
        return result

    def check_bad_flag(value, value_flag, contains, excludes):
        """ Make sure value is found in contains, but not found in excludes. """
        result = value
        if not value is None:
            i = 0
            while (not result is None) and ((i < len(contains)) or (i < len(excludes))):
                if not value in contains[i if i < len(contains) else len(contains)]:
                    result = None
                    PRINT.warn("False-negative found in test-data for {0}, so it was omitted.".format(value_flag))
                if value in excludes[i if i < len(excludes) else len(excludes)]:
                    result = None
                    PRINT.warn("False-positive found in test-data for {0}, so it was omitted.".format(value_flag))
                i = i + 1

        return result

    #-- Init check strings
    check_t = None if is_null_or_empty(str_true) else str_true
    check_f = None if is_null_or_empty(str_false) else str_false

    #-- First check: Make sure A does not include B
    check_t = check_subset(check_t, check_f, "-true", "-false")
    check_f = check_subset(check_f, check_t, "-false", "-true")

    if not test_tf is None:
        #-- Second check: Make sure we eliminate false-positives
        check_t = check_bad_flag(check_t, "-true", test_tf[0], test_tf[1])
        check_f = check_bad_flag(check_f, "-false", test_tf[1], test_tf[0])

        if (check_t is None) and (check_f is None):
            #-- Disaster recovery: Attempt an autodetect
            PRINT.info("Attempting to auto-detect any unique good/bad login strings.")
            html_t, html_f = get_or_autodetect_tf(test_tf)
            if (len(html_t) + len(html_f)) > 0:
                check_t = html_t[0] if len(html_t) > 0 else None
                check_f = html_f[0] if len(html_f) > 0 else None
                PRINT.info("Success!\n  -> -true: '{}'\n  -> -false: '{}'".format(check_t, check_f))
            else:
                PRINT.fail("Could not auto-detect a unique good/bad login string.")
    else:
        #-- We don't have any test-data to work with
        if (check_t is None) and (check_f is None):
            PRINT.fail("No valid unique good/bad login string passed. Consider using the -test arg.")
        elif (check_t is None) or (check_f is None):
            PRINT.warn("Only one valid good/bad login string passed. Consider using both or using the -test arg to auto-detect them.")
        else:
            PRINT.warn("The good/bad login strings weren't tested. Consider using -test arg to verify them.")

    return (check_t, check_f)


def get_victims(single_victim, victim_file):
    """ Builds and returns a sorted victims list. """
    PRINT.info("Preparing hit-list...")
    hit_list = set()

    if not single_victim is None:
        #-- Explicit victim
        PRINT.info("Added '{}' explicitly from -u.".format(single_victim[0]), 1)
        hit_list.add(single_victim[0])
    
    if not victim_file is None:
        #-- Read file into attack_user
        try:
            PRINT.info("Reading victims file: '{}'.".format(victim_file[0]))
            f = open(victim_file[0], 'r')
            last_output = time.time()
            total = 0
            while True:
                #- Read
                line = file.readline()
                if not line: 
                    #-- EOF
                    break
                total = total + 1

                #-- Process
                t_victim = line.replace("\r", "").replace("\n", "")
                if not t_victim in hit_list:
                    if PRINT.debug("Added '{}'".format(t_victim), 1):
                        last_output = time.time()

                    hit_list.add(t_victim)
                else:
                    if PRINT.debug("Skipped duplicate entry '{}'".format(t_victim), 1):
                        last_output = time.time()

                if time.time() - last_output > 5:
                    last_output = time.time()
                    PRINT.info("Added {} entries of {} to hitlist (i'm still working, i haven't stalled)".format(len(hit_list), total))
            f.close()

            if len(hit_list) == 0:
                PRINT.fail("The file specified by -U appears to be empty.")

            PRINT.info("Done")

        except FileNotFoundError:
            PRINT.fail("The file specified by -U does not exist.")
        except e:
            PRINT.fail("There was a problem processing the file specified:", fatal_error=False)
            PRINT.fail(str(e), 1)

    if len(hit_list) == 0:
        PRINT.fail("No target user(s) specified (help: '-u' or '-U')")

    #-- Finish up
    if len(hit_list) == 1:
        hit_list = list(hit_list)
    else:
        PRINT.info("Sorting hit-list...", 1)
        hit_list = sorted(hit_list)
    PRINT.info("Hit-list with [{}] name{} ready.".format(len(hit_list), ("" if len(hit_list) == 1 else "s")))

    #-- Result
    return hit_list


#=============================================================================================================[ MAIN ]==
#   - https://kushaldas.in/posts/using-python-to-access-onion-network-over-socks-proxy.html

args = Commandline("-h", "-H", USE_COLOR, DEFAULT_VERBOSITY)
PRINT = Print(USE_COLOR, DEFAULT_VERBOSITY)

if is_online():
    #-- Override Constants and Defaults
    GET_IP = args.get("-getip") if args.is_set("-getip") else GET_IP
    VERIFY = args.get("-verify") if args.is_set("-verify") and (args.get("-verify") > 0) else VERIFY
    
    if args.is_set("-v") and (args.get("-v") in range(Print.VERBOSITY_FAIL, Print.VERBOSITY_DEBUG)):
        Print.verbosity = args.get("-v")
    elif args.is_set("-v"):
        PRINT.info("Arg -v has a value of '{}' but needs to be between 0 and 3 (inclusive).".format(args.get("-v")))

    #-- Set flags
    f_badssl = args.is_set("-badssl")

    #-- Set up the socks5 proxy
    proxy = None
    if args.is_set("-tor"):
        PRINT.debug("Using Tor [ {} ]".format(args.value["-tor"][0]))
        tor_socks = "socks5h://{}".format(args.value["-tor"][0])
        proxy = { "http": tor_socks, "https": tor_socks, "ftp": tor_socks }
    else:
        PRINT.warn("Not using Tor")


    #-- Main
    if args.is_set("-ip"):
        #-- Print the IP and exit
        print_ips(f_badssl, proxy)
    elif args.is_set("-url"):
        #-- Prepare for an attack
        hit_list = get_victims(args.get("-u"), args.get("-U"))
        test_data = get_test_data(args.get("-url"), args.get("-test"), VERIFY, f_badssl, proxy)
        str_true, str_false = get_truefalse(args.get("-true"), args.get("-false"), test_data)

        #-- Attack!
        # TODO
    else:
        PRINT.fail("You need to specify a target site with -url.")
else:
    PRINT.fail("You need an internet connection to use NotHydra.")
