from gatex.parser.scan import Scanner

if __name__ == "__main__":
    scanner = Scanner()
    scanner.load_file("test/gtx/test.gtx")
    scanner.match()
