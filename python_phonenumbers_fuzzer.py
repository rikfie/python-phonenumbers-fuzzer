#!/usr/bin/python3

# Copyright 2020 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import sys, struct, time
import atheris
import phonenumbers
from phonenumbers import NumberParseException

def test_parse(inp):
    try:
        pn = phonenumbers.parse(inp, None)
        phonenumbers.is_possible_number(pn)
    except NumberParseException:
        return

def test_matcher(inp):
    phonenumbers.PhoneNumberMatcher(inp, "US")
    
def test_input_digit(inp):
    #try:
    formatter = phonenumbers.AsYouTypeFormatter("US")
    formatter.input_digit(inp)
    #except TypeError:
    #    return
    
    
tests = [
    test_parse,
    test_matcher,
    test_input_digit,
]

def TestOneInput(input_bytes):
    if len(input_bytes) < 1:
        return
    choice = struct.unpack('>B', input_bytes[:1])[0]
    if choice >= len(tests):
        return
    fdp = atheris.FuzzedDataProvider(input_bytes[1:])
    inp = fdp.ConsumeUnicode(sys.maxsize)
    tests[choice](inp)

def main():
    atheris.Setup(sys.argv, TestOneInput, enable_python_coverage=False)
    atheris.Fuzz()


if __name__ == "__main__":
    atheris.instrument_all()
    main()
