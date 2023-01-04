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
""" Harnass for fuzzing https://github.com/daviddrysdale/python-phonenumbers.git """

import sys
import struct
import atheris
import phonenumbers
from phonenumbers import NumberParseException

def test_parse(inp):
    """ Testing phonenumbers parse method """
    try:
        phone_number = phonenumbers.parse(inp, None)
        phonenumbers.is_possible_number(phone_number)
    except NumberParseException:
        return

def test_matcher(inp):
    """ Testing phonenumbers PhoneNumberMatcher method """
    phonenumbers.PhoneNumberMatcher(inp, "US")

def test_input_digit(inp):
    """ Testing phonenumbers AsYouTypeFormatter / input_digit method """
    try:
        formatter = phonenumbers.AsYouTypeFormatter("US")
        formatter.input_digit(inp)
    except TypeError:
        return


TESTS = [
    test_parse,
    test_matcher,
    test_input_digit,
]

def test_one_input(input_bytes):
    """ Fuzzer's entry point """
    if len(input_bytes) < 1:
        return
    choice = struct.unpack('>B', input_bytes[:1])[0]
    if choice >= len(TESTS):
        return
    fdp = atheris.FuzzedDataProvider(input_bytes[1:])
    inp = fdp.ConsumeUnicode(sys.maxsize)
    TESTS[choice](inp)

def main():
    """ main function """
    atheris.Setup(sys.argv, test_one_input, enable_python_coverage=False)
    atheris.Fuzz()


if __name__ == "__main__":
    atheris.instrument_all()
    main()
