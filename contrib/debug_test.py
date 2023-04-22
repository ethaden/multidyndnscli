def run():
    print ('Test')
    try:
        raise Exception("Test")
        1 / 0                #@IgnoreException
    except:
        pass

    func = lambda: 1 / 0     #@IgnoreException
    try:
        func()               #@IgnoreException
    except:
        pass

run()
