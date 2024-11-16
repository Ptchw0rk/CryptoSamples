//
// Created by patch on 13/11/24.
//

#ifndef TESTS_H
#define TESTS_H
#include <cppunit/extensions/HelperMacros.h>
#include <cppunit/extensions/TestFactoryRegistry.h>

#include "CryptoUtils.h"

class Tests : public CppUnit::TestFixture {
public:
    CPPUNIT_TEST_SUITE(Tests);
    CPPUNIT_TEST(testPrivKeyGen);
    CPPUNIT_TEST(testPubKeyGen);
    CPPUNIT_TEST(testCertGen);
    CPPUNIT_TEST(testCertCheck);
    CPPUNIT_TEST(testExportLoadCert);
    CPPUNIT_TEST(testSignData);
    CPPUNIT_TEST(testSymEncrypt);
    CPPUNIT_TEST(testAsymEncrypt);
    CPPUNIT_TEST_SUITE_END();
public:
    //Tests();
    //~Tests() override;
protected:
    static EVP_PKEY_ptr testPrivKeyGen();
    static void testPubKeyGen();
    static void testCertGen();
    static void testCertCheck();
    static void testExportLoadCert();
    static void testSignData();
    static void testSymEncrypt();
    static void testAsymEncrypt();
};




#endif //TESTS_H
