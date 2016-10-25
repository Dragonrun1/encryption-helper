<?php
declare(strict_types = 1);
/**
 * Contains class EncryptionHelper.
 *
 * PHP version 7.0+
 *
 * Copyright (C) 2016 Michael Cummings
 *
 * @author    Michael Cummings <mgcummings@yahoo.com>
 * @copyright 2016 Michael Cummings
 * @license   GPL-3.0+
 * @link      http://spdx.org/licenses/GPL-3.0.html
 */
namespace DataAccess;

class EncryptionHelper
{
    /**
     * EncryptionHelper constructor.
     *
     * Constructor is very fat for what is usually considered good practice in PHP but left it alone to make it easier
     * to compare with original c# version.
     *
     * @param string $encryptedData
     * @param string $keyString
     * @param string $keyBytes
     *
     * @uses EncryptionHelper::setKeyBytes()
     * @uses EncryptionHelper::setKeyString()
     * @uses EncryptionHelper::decrypt()
     * @uses EncryptionHelper::computedCheckSum()
     */
    public function __construct(
        string $encryptedData,
        string $keyString = 'ABC12345',
        string $keyBytes = "\x11\x12\x13\x14\x15\x16\x17\x18"
    ) {
        $this->setKeyBytes($keyBytes)
             ->setKeyString($keyString);
        // Decrypt string
        $data = $this->decrypt($encryptedData);
        // Parse out key/value pairs and add to dictionary
        $checksum = null;
        $args = explode('&', $data);
        /**
         * @var string $arg
         */
        foreach ($args as $arg) {
            $i = strpos($arg, '=');
            if (false !== $i) {
                $key = substr($arg, 0, $i);
                $value = substr($arg, $i + 1);
                if ($key === $this->checksumKey) {
                    $checksum = $value;
                } else {
                    $this->dictionary[urldecode($key)] = urldecode($value);
                }
            }
        }
        if ($checksum === null || $checksum !== $this->computedCheckSum()) {
            $this->dictionary = [];
        }
    }
    /**
     * @return string
     * @uses EncryptionHelper::computedCheckSum()
     */
    public function __toString()
    {
        // Build query string from current contents
        /*
         * Example of my original line for line conversion from c# to have for comparision to final code.
         * $content = '';
         * foreach (array_keys($this->dictionary) as $key) {
         *     if (strlen($content) > 0) {
         *          $content .= '&';
         *     }
         *     $content .= sprintf('%s=%s', urlencode($key), urlencode($this->dictionary[$key]));
         * }
         * if (strlen($content) > 0) {
         *     $content .= '&';
         * }
         * $content .= sprintf('%s=%s', $this->_checksumKey, $this->computedCheckSum());
         * return $content;
         */
        $content = [];
        foreach ($this->dictionary as $key => $value) {
            $content[] = sprintf('%s=%s', urlencode($key), urlencode($value));
        }
        $content[] = sprintf('%s=%s', $this->checksumKey, $this->computedCheckSum());
        return implode('&', $content);
    }
    /**
     * Used to decrypt an encode string.
     *
     * Made this public to easy testing plus allows the class to be used in ways the original c# class wasn't.
     *
     * @param string $text
     *
     * @return string
     * @uses EncryptionHelper::getBytes()
     * @uses EncryptionHelper::removePadding()
     */
    public function decrypt(string $text): string
    {
        $keyData = substr($this->keyString, 0, 8);
        $decrypted = mcrypt_decrypt(MCRYPT_DES, $keyData, $this->getBytes($text), MCRYPT_MODE_CBC, $this->keyBytes);
        if (false === $decrypted) {
            return '';
        }
        $decrypted = $this->removePadding($decrypted);
        return $decrypted;
    }
    /**
     * Used to encrypt a string.
     *
     * Made this public to easy testing plus allows the class to be used in ways the original c# class wasn't.
     *
     * @param string $text
     *
     * @return string
     * @uses EncryptionHelper::addPadding()
     * @uses EncryptionHelper::getString()
     */
    public function encrypt(string $text): string
    {
        $keyData = substr($this->keyString, 0, 8);
        $text = $this->addPadding($text);
        $encrypted = mcrypt_encrypt(MCRYPT_DES, $keyData, $text, MCRYPT_MODE_CBC, $this->keyBytes);
        if (false === $encrypted) {
            return '';
        }
        return $this->getString($encrypted);
//        return $encrypted;
    }
    /**
     * Used to set binary string value for 'iv'.
     *
     * Through not in the original c# class this makes it nicer to re-use in other ways.
     *
     * @param string $value
     *
     * @return $this Fluent interface
     */
    public function setKeyBytes(string $value)
    {
        $this->keyBytes = $value;
        return $this;
    }
    /**
     * Used to set binary string value for the 'key'.
     *
     * Through not in the original c# class this makes it nicer to re-use in other ways.
     *
     * @param string $value
     *
     * @return $this Fluent interface
     */
    public function setKeyString(string $value)
    {
        $this->keyString = $value;
        return $this;
    }
    /**
     * Used to add padding to the data being encrypt in the unique way .NET has of doing so.
     *
     * @param string $data
     *
     * @return string
     */
    private function addPadding(string $data): string
    {
        $padding = 8 - (strlen($data) % 8);
        return $data . str_repeat(chr($padding), $padding);
    }
    /**
     * Used to create and validate query checksum value.
     *
     * @return string
     */
    private function computedCheckSum(): string
    {
        $checksum = 0;
        $zero = ord('0');
        $func = function ($acc = 0, $value) use ($zero) {
            foreach (str_split($value) as $item) {
                $acc += ord($item) - $zero;
            }
            return $acc;
        };
        $checksum += array_reduce(array_keys($this->dictionary), $func);
        $checksum += array_reduce($this->dictionary, $func);
        return sprintf('%X', $checksum);
    }
    /**
     * @param string $data
     *
     * @return string
     */
    private function getBytes(string $data): string
    {
        // getString() encodes the hex-numbers with two digits
        $results = '';
//        for ($i = 0, $dataLen = strlen($data); $i < $dataLen; $i += 2) {
//            $results .= pack('H', substr($data, $i, 2));
//        }
        foreach (str_split($data, 2) as $chunk) {
            $results .= chr(hexdec($chunk));
        }
        return $results;
    }
    /**
     * @param string $data
     *
     * @return string
     */
    private function getString(string $data): string
    {
        $results = '';
        foreach (str_split($data) as $byte) {
            $results .= sprintf('%02X', ord($byte));
        }
        return $results;
    }
    /**
     * Remove the .NET unique padding from decrypted string.
     *
     * @param string $data
     *
     * @return string
     */
    private function removePadding(string $data): string
    {
        $padding = substr($data, -1);
        // Pads to next block so no more than 8 chars.
        if (9 >= ord($padding)) {
            return rtrim($data, $padding);
        }
        return $data;
    }
    /**
     * Name for checksum value (unlikely to be used as arguments by user)
     *
     * @var string $checksumKey
     */
    private $checksumKey = "__$$";
    /**
     * Hold associate array of the query string keys and values.
     *
     * In the original c# code the class had to extend from another template class just to get something like this.
     * Makes you really appreciate how easy some things are in PHP.
     *
     * @var array $dictionary
     */
    private $dictionary = [];
    /**
     * Change the following key to ensure uniqueness
     * Must be 8 bytes
     *
     * Originally was going to use array like from c# but string is easier to use direct in mcrypt.
     * $_keyBytes = [0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18];
     *
     * This is better know as an 'iv' in PHP etc.
     *
     * @var string $keyBytes
     */
    private $keyBytes;
    /**
     * Must be at least 8 characters
     *
     * @var string $keyString
     */
    private $keyString;
}
