import subprocess
import os
from colorama import Fore, Style
import tempfile

tf = tempfile.TemporaryDirectory()

with open(tf.name+"/chal.tex", "w") as tex_file:
    tex_file.write(rf"""
\documentclass{{article}}
\usepackage{{lipsum}} 
\usepackage{{fancyhdr}}
\usepackage{{lastpage}}
\pagestyle{{fancy}}

\pagenumbering{{gobble}}
\lfoot{{ % Page number formatting 
    \hspace*{{\fill}} Page \arabic{{page}} % of \protect\pageref{{LastPage}}
    }}

\newif\iflong
% \longtrue
\longfalse

\newenvironment{{absolutelynopagebreak}}
  {{\par\nobreak\vfil\penalty0\vfilneg
   \vtop\bgroup}}
  {{\par\xdef\tpd{{\the\prevdepth}}\egroup
   \prevdepth=\tpd}}

\begin{{document}}
% \begin{{absolutelynopagebreak}}
""")

    print("")
    print(Fore.RED + "Insert your message in a LaTeX syntax. (For example, \\texttt{b01ler up!})")
    print("")
    print(Fore.RED + "Hit Enter once you are done.")
    print(Style.RESET_ALL)
    
    input_value = input()

    print("")
    print(Fore.RED + "Compiling...")
    print(Fore.RED + "(This might take a while. Feel free to hit Enter multiple times if that'd reduce your anxiety lol.)")

    tex_file.write(rf"""

    Here is my response to your message. It should all be in text. I hope you can see it.

    You said:

    {input_value}

    My reply:

    \nopagebreak 

    % \begin{{absolutelynopagebreak}}

    \iflong 

    \smash{{
        \begin{{minipage}}[t]{{\textwidth}}
        \lipsum[1-4]
        \vspace{{1cm}} \linebreak 
        \raggedright Wait! I am not done yet! Keep scrolling please!  
        \vspace{{1cm}} \linebreak
        \lipsum[5-6]
        \vspace{{1cm}} \linebreak 
        \raggedright You are almost there. Please keep scrolling!
        \vspace{{1cm}} \linebreak
        \lipsum[7]
        \vspace{{1cm}} \linebreak 
        \raggedright So anyway, TL;DR is (Replace the blanks with underscores): 
        \vspace{{1cm}} \linebreak
        \raggedright bctf\{{WH47\_Y0U\_533\_15\_WH47\_Y0U\_G37,\_L473X\}}
        \vspace{{1cm}} \linebreak
        \lipsum[1-10]
        \vspace{{1cm}} \linebreak 
        \raggedright Again anyway, TL;DR is (Replace the blanks with underscores):
        \vspace{{1cm}} \linebreak
        \raggedright bctf\{{WH47\_Y0U\_533\_15\_WH47\_Y0U\_G37,\_L473X\}}
        \vspace{{1cm}} \linebreak
        \end{{minipage}}
    }}
    \fi
    % \end{{absolutelynopagebreak}}
    % \end{{samepage}}
\end{{document}}
""")

subprocess.run(["pdflatex", "--no-shell-escape", "-output-directory="+tf.name, tf.name+"/chal.tex"], stdout=subprocess.DEVNULL)

print("")
print(Fore.RED + "This is what it looks like when the PDF file is converted to a txt file:")
print("")
print(Style.RESET_ALL)

subprocess.run(["pdftotext", tf.name+"/chal.pdf"])
subprocess.run(["cat", tf.name+"/chal.txt"])

# subprocess.run(["rm", tf.name+"/chal.tex", tf.name+"/chal.pdf", tf.name+"/chal.txt", tf.name+"/chal.log", tf.name+"/chal.aux"])

tf.cleanup()

print(Fore.RED + "End of the file.")
print("")

print(Fore.RED + "Due to security reasons, we will not be giving you the PDF or log files. Sorry =(")
print("")
print(Style.RESET_ALL)
