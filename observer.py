#!/usr/bin/env python

# This is the simple observer design pattern

from abc import ABCMeta, abstractmethod

class Observable(object):

    # This object must be singleton to communicate convenience
    __instance = None
    __observers = []

    def __new__(cls):
        if cls.__instance == None:
            print "creating observable"
            cls.__instance = object.__new__(cls)
            #cls.__instance.name = "The one"
        print "returning observable"
        print cls.__instance
        __observers = []
        return cls.__instance

    def __init__(self):
        self.observers = self.__observers

    def register(self, observer):
        if not observer in self.observers:
            self.observers.append(observer)
        for i in self.observers:
            print i

    def unregister(self, observer):
        if observer in self.observers:
            self.observers.remove(observer)

    def unregister_all(self):
        if self.observers:
            del self.observers[:]

    def send_msg(self, target, msg_type, msg):
        for observer in self.observers:
            if observer.name == target:
                observer.on_message(msg_type, msg)


class Observer(object):
    __metaclass__ = ABCMeta

    def __init__(self, name):
        self.name = name

    @abstractmethod
    def on_message(self, msg_type, msg):
        pass

class TestObserver0(Observer):
    def __init__(self, observable):
        super(TestObserver0, self).__init__("TestObserver0")
        self.observable = observable
        self.msg = "I am TestObserver0"
        print ("0 registering")
        self.observable.register(self)

    def on_message(self, msg_type, msg):
        print("I'm TestObserver0 Got type:{0} message : {1}".format(msg_type, msg))

    def send_message_to_TestObserver1(self):
        self.observable.send_msg("TestObserver1", "control", self.msg)
        print("sent message to observer 1")

class TestObserver1(Observer):
    def __init__(self, observable):
        super(TestObserver1, self).__init__("TestObserver1")
        self.observable = observable
        self.msg = "I am TestObserver1"
        print ("1 registering")
        self.observable.register(self)

    def on_message(self, msg_type, msg):
        print("I'm TestObserver1 Got type:{0} message : {1}".format(msg_type, msg))

    def send_message_to_TestObserver0(self):
        self.observable.send_msg("TestObserver0", "data", self.msg)
        print("sent message to observer 0")



if __name__ == "__main__":
    #observable = Observable()
    #test0 = TestObserver0(observable)
    #test1 = TestObserver1(observable)
    test0 = TestObserver0(Observable())
    test1 = TestObserver1(Observable())
    test0.send_message_to_TestObserver1()
    test1.send_message_to_TestObserver0()

