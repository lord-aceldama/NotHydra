#!/usr/bin/python3
from html.parser import HTMLParser
import requests
import sys


#================================================================================================[ GLOBAL CONSTANTS ]==
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

#----------------------------------------------------------------------------------------------------------------------
DEFAULT_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:76.0) Gecko/20100101 Firefox/76.0"
GET_IP = "http://icanhazip.com/"
CMD_LN = {
    "-h"        : (None, "Shows this help menu.", None, "Help"),
    "-ip"       : (None, "Gets the ip from {} and exits immediately.".format(GET_IP), "-tor", "Get IP"),
    "-badssl"   : (None, "Ignore bad ssl certificates.", None, ""),
    "-tor"      : ([str], "The TOR control ip and port, eg. localhost:9050", "-ip", "TOR"),
    "-url"      : ([str], "The url containing the login form. (required)", None, "Form Url"),
    "-test"     : ([str, str], "A valid user/pass combination to test.", None, "Valid User"),
    "-u"        : ([str], "The user to target.", "-U", "User"),
    "-U"        : ([str], "A file with a list of users to target.", "-u", "Userlist"),
    "-w"        : ([str], "A file with a list of passwords to test.", "-W", "Wordlist"),
    #"-W"        : ([str], "A url containing a list of passwords to test.", "-w", "Remote wordlist"),
    "-r"        : ([int], "Line number in wordlist to resume at.", "-R", "Resume at index"),
    "-R"        : ([str], "Word in wordlist to resume at.", "-r", "Resume at word"),
    "-len"      : ([int, int], "Min-max length inclusive.", "-c", "Password length"),
    "-getip"    : ([str], "Override for {}".format(GET_IP), "-ip", "Get IP"),
    "-c"        : ([str], "Characters allowed in the password.", "-len", "Charset"),
    "-true"     : ([str], "String in response body if user/password is correct.", "-false", "Success"),
    "-false"    : ([str], "String in response body if user/password is wrong.", "-true", "Failed"),
    "-ua"       : ([str], "Custom UserAgent string to use.", None, ""),
    "-cookie"   : ([str], "Custom cookie to use.", None, ""),
    "-head"     : ([str, str], "Custom HTTP header to send.", None, ""),
    "-loot"     : ([str], "Filename to dump successful results in.", None, ""),
    "-verify"   : ([int], "Verify result N times.", None, ""),
    "-threads"  : ([int], "Number of parallel threads.", None, "")
}


#=========================================================================================================[ CLASSES ]==
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
                if form[0]:
                    self._L.append(form[1:])

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
        """
        if tag == "form":
            self._is_in_form = True
            self._forms.append([False, {  k : v for k,v in attrs }])
        elif self._is_in_form and ("name" in [ k  for k, v in attrs ]):
            L = dict({"name" : None, "value" : None})
            for k,v in attrs:
                if (k == "type"):
                    if (v == "password"):
                        self._forms[-1][0] = True
                elif k in ["name", "value"]:
                    L[k] = v

            self._forms[-1].append(L)

        return

    def handle_endtag(self, tag):
        """ Parse closing tags
        """
        if self._is_in_form and (tag == "form"):
            self._is_in_form = False

        return


#----------------------------------------------------------------------------------------------------------------------
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


#----------------------------------------------------------------------------------------------------------------------
class Commandline():
    #-- Properties
    @property
    def value(self) -> dict:
        """ Returns all parsed command line args as a dictionary. """
        return self._parsed


    #-- Constructor
    def __init__(self, help_arg : str):
        """ Parses command line args. if the help-arg is supplied, it prints the help menu and exits immediately. """
        #-- Show splash screen
        print(SPLASH)

        if (len(sys.argv) == 1) or (help_arg in sys.argv[1:]):
            #-- Show help and exit
            self.help()
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
                #print("{}: ['{}']".format(key.rjust(8), "', '".join(values)))
                if not values is True:
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

    def get(self, key:str):
        """ Returns a value if it is set, or None if not. """
        result = None 
        if self.is_set(key):
            result = self._parsed[key]
        return result

    def help(self, text=None):
        """ Shows help with an error message (if provided). """
        print("GBH HALP:")
        if not text is None:
           print("  ERROR: {}\n".format(text))
        
        print("  ARGS:")
        keys = list()
        for x in sorted(CMD_LN.keys()):
            y = "" if CMD_LN[x][0] is None else "<{}>".format("> <".join([x.__name__ for x in CMD_LN[x][0]]))
            keys.append([x, y])

        for key, value in keys:
            h = CMD_LN[key][1]
            if not CMD_LN[key][2] is None:
                h = h + "  (also: " + CMD_LN[key][2] + ")"
            
            print("    {} : {}".format("{} {}".format(key, value).strip().ljust(17), h))
        print("\n\n")
        exit(0)


#=========================================================================================================[ METHODS ]==
def IsOnline() -> bool:
    try:
        r = requests.get('http://www.google.com/')
        return True
    except requests.exceptions.HTTPError as err:
        return False


#============================================================================================================[ MAIN ]==
#   - https://kushaldas.in/posts/using-python-to-access-onion-network-over-socks-proxy.html
#   - https://stackoverflow.com/questions/55649421/how-to-check-if-there-is-internet-connection

args = Commandline("-h")
if IsOnline():
    #-- Set flags
    f_badssl = args.is_set("-badssl")

    #-- Set the proxy
    proxy = None
    if args.is_set("-tor"):
        tor_socks = "socks5h://{}".format(args.value["-tor"])
        proxy = { "http": tor_socks, "https": tor_socks }

    #-- Main
    if args.is_set("-ip"):
        #-- Print the IP and exit
        src = "CLEARNET"
        try:
            #-- Fetch clearnet IP
            r = requests.get(GET_IP, verify=f_badssl)
            print("  {} IP: {}".format(src, r.content.decode("utf-8")))
            if not proxy is None:
                #-- Fetch TOR IP
                src = "PROXY"
                r = requests.get(GET_IP, proxies=proxy, verify=f_badssl)
                print("  {} IP: {}".format(src, r.content.decode("utf-8")))
        except requests.exceptions.HTTPError as err:
            print("  ERROR: Trouble getting {} IP from '{}'.".format(src.lower(), GET_IP))
            print("    ->", err)
        print("\n")
    elif args.is_set("-url"):
        #-- Attack!

        pass
    else:
        pass
else:
    print("ERROR: You need an internet connection\n\n")

