sslscan
=======

SSL certificate scanner.

Scans through a list of websites, captures SSL Server Certificate security details,
sorts Certificates' data as per their validity, and exports data file.

# Requirements:

* python >= 3.9
* pyopenssl >= 20.0.1

# Usage

```
$ ./sslscan.py -h
usage: sslscan.py [-h] [input] [output]

SSL certificate scanner. Scans through a list of websites, captures SSL Server
Certificate security details, sorts Certificates' data as per their validity,
and exports data file.

positional arguments:
  input       list of websites (file name or - for stdin, defaults to stdin)
  output      certificate data (file name or - for stdout, defaults to stdout)

optional arguments:
  -h, --help  show this help message and exit
```

# Files

* [Dockerfile](Dockerfile) - Dockerfile
* [main.yml](.github/workflows/main.yml) - GitHub Workflow
* [requirements.txt](requirements.txt) - Python requirements
* [sslscan.py](sslscan.py) - Python code
* [test.txt](test.txt) - Test input
