#!/usr/bin/env python3

import random
 

def prob(num_people):
    date = [False] * 365

    for i in range(num_people + 2):
        birthday = random.randint(0, 364)
        if date[birthday]:
            return True
        else:
            date[birthday] = True
    return False

def test(num_trials, people):
    successes = 0
    for i in range(num_trials):
        if prob(people):
            successes += 1
    return successes

def input_int_range(low, high):
    while True:
        int_range = int(input("What threshold would you like? (enter as percent) "))
        if int_range > high or int_range < low:
            print(f"The value {int_range} is not within valid range")
        else:
            return int_range

def main():
    num_trials = 100000
    people = 100
    threshold = 0
    allowed_input = input_int_range(1, 100)

    for people in range(num_trials):
        #this breaks the running loop when threshold exceeds input we are asking for
        if threshold > allowed_input:
            break
        successes = test(num_trials, people)
        threshold = (successes / num_trials) * 100
        #"+2" is added to the print statement below because we need at least 2 people to have a probability of a shared birthday
        print(f"For {people + 2} people, the probability of a shared birthday was {successes} / {num_trials} or {round(threshold, 2)}%")
        percent = int(allowed_input)
    print(f"To achieve at least {percent}% probability of a collision, need {people + 1} people in the room")

main()