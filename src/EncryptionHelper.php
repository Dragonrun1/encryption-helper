<?php
declare(strict_types = 1);
/**
 * Contains class EncryptionHelper.
 *
 * PHP version 7.0+
 *
 * LICENSE:
 * This file is part of Encryption Helper - Use to help with the encryption and decryption of GET queries.
 * Copyright (C) 2016 Michael Cummings
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; version 2 of the License.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, you may write to
 *
 * Free Software Foundation, Inc.
 * 59 Temple Place, Suite 330
 * Boston, MA 02111-1307 USA
 *
 * or find a electronic copy at
 * <http://spdx.org/licenses/GPL-2.0.html>.
 *
 * You should also be able to find a copy of this license in the included
 * LICENSE file.
 *
 * @author    Michael Cummings <mgcummings@yahoo.com>
 * @copyright 2016 Michael Cummings
 * @license   GPL-2.0
 */
namespace EncryptionHelper;

class EncryptionHelper
{
    /**
     * EncryptionHelper constructor.
     *
     * Constructor is very fat for what is usually considered good practice in PHP but re-factored most of it out into
     * another method while still keeping code comparable to the same code in c# original.
     *
     * @param string $encryptedData Data to be decrypted into query list
     * @param string $key Encryption key
     * @param string $initVector Encryption initialization vector
     *
     * @uses EncryptionHelper::setInitVector()
     * @uses EncryptionHelper::setKey()
     * @uses EncryptionHelper::decrypt()
     * @uses EncryptionHelper::processQueryString()
     * @throws \RangeException
     * @throws \RuntimeException
     */
    public function __construct(
        string $encryptedData,
        string $key = 'ABC12345',
        string $initVector = "\x11\x12\x13\x14\x15\x16\x17\x18"
    ) {
        $this->setInitVector($initVector)
             ->setKey($key);
        // Decrypt string
        $data = $this->decrypt($encryptedData);
        $this->processQueryString($data);
    }
    /**
     * Returns query string using current contents.
     *
     * @return string
     * @uses EncryptionHelper::computedCheckSum()
     */
    public function __toString()
    {
        /*
         * Example of my original line for line conversion from c# to have for comparision to final code.
         * $content = '';
         * foreach (array_keys($this->dictionary) as $name) {
         *     if (strlen($content) > 0) {
         *          $content .= '&';
         *     }
         *     $content .= sprintf('%s=%s', urlencode($name), urlencode($this->dictionary[$name]));
         * }
         * if (strlen($content) > 0) {
         *     $content .= '&';
         * }
         * $content .= sprintf('%s=%s', $this->_checksumKey, $this->computedCheckSum());
         * return $content;
         */
        $content = [];
        foreach ($this->queries as $name => $value) {
            $content[] = sprintf('%s=%s', urlencode($name), urlencode($value));
        }
        /*
         * Probably bug in original c# code since these should also be url encoded but not changing without feedback.
         */
        $content[] = sprintf('%s=%s', $this->checksumName, $this->computedCheckSum());
        return implode('&', $content);
    }
    /**
     * Allows add new queries to contents.
     *
     * @param string $name
     * @param string $value
     */
    public function addQuery(string $name, string $value)
    {
        $this->queries[$name] = $value;
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
        $decrypted = mcrypt_decrypt($this->cipher, $this->getKey(), $this->getBytes($text), MCRYPT_MODE_CBC,
            $this->getInitVector());
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
        $text = $this->addPadding($text);
        $encrypted = mcrypt_encrypt($this->cipher, $this->getKey(), $text, MCRYPT_MODE_CBC, $this->getInitVector());
        if (false === $encrypted) {
            return '';
        }
        return $this->getString($encrypted);
    }
    /**
     * Check if a named query exists in content.
     *
     * @param string $name
     *
     * @return bool
     */
    public function hasQuery(string $name): bool
    {
        return array_key_exists($name, $this->queries);
    }
    /**
     * Parse out name/value pairs and add to query list.
     *
     * @param string $data
     *
     * @uses EncryptionHelper::computedCheckSum()
     */
    public function processQueryString(string $data)
    {
        $checksum = null;
        $args = explode('&', $data);
        /**
         * @var string $arg
         */
        foreach ($args as $arg) {
            $i = strpos($arg, '=');
            if (false !== $i) {
                /*
                 * Url decoding should probably happen here so everything include the checksum are done correctly but
                 * didn't change to be compatible with C# original code awaiting feedback.
                 */
                $name = substr($arg, 0, $i);
                /*
                 * Probably bug in original c# code since this should also be url decoded but not changing without
                 * feedback.
                 */
                $value = substr($arg, $i + 1);
                if ($this->checksumName === $name) {
                    $checksum = $value;
                } else {
                    $this->queries[urldecode($name)] = urldecode($value);
                }
            }
        }
        if ($checksum === null || $checksum !== $this->computedCheckSum()) {
            $this->queries = [];
        }
    }
    /**
     * Allows remove existing query from content.
     *
     * @param string $name
     *
     * @return bool Returns true if query existed and was removed else false.
     */
    public function removeQuery(string $name)
    {
        if (array_key_exists($name, $this->queries)) {
            unset($this->queries[$name]);
            return true;
        }
        return false;
    }
    /**
     * @param string $value
     *
     * @return $this Fluent interface
     * @throws \RangeException
     */
    public function setCipher(string $value = MCRYPT_DES)
    {
        if (!in_array($value, mcrypt_list_algorithms(), true)) {
            $message = sprintf('Cipher %s is not known', $value);
            throw new \RangeException($message);
        }
        $current = $this->cipher;
        try {
            $this->setKey($this->key)
                 ->setInitVector($this->initVector);
        } catch (\Exception $exc) {
            $this->cipher = $current;
            $message = 'Cipher could not be changed because either current key or initialization vector are not'
                . ' compatible with new cipher';
            throw new \RangeException($message, 1, $exc);
        }
        $this->cipher = $value;
        return $this;
    }
    /**
     * Used to set binary string value for initialization vector.
     *
     * Through not in the original c# class this makes it nicer to re-use in other ways.
     *
     * NOTE: Use of a plain text vector is not a good idea. It is much better to use some sort of binary string.
     *
     * @param string $value
     *
     * @return $this Fluent interface
     * @throws \RangeException
     * @throws \RuntimeException
     */
    public function setInitVector(string $value)
    {
        $size = mcrypt_get_iv_size($this->cipher, MCRYPT_MODE_CBC);
        if (false === $size) {
            $message = 'Failed to get required vector size';
            throw new \RuntimeException($message);
        }
        if ($size > strlen($value)) {
            $message = sprintf('Initialization vector must be at least %s characters long', $size);
            throw new \RangeException($message);
        }
        $this->ivSize = $size;
        $this->initVector = $value;
        return $this;
    }
    /**
     * Used to set binary string value for the 'key'.
     *
     * Value will be truncated to correct size for the cipher used.
     *
     * NOTE: Use of a plain text key is not a good idea. It is much better to use some sort of binary string key.
     *
     * Through not in the original c# class this makes it nicer to re-use in other ways.
     *
     * @param string $value
     *
     * @return $this Fluent interface
     * @throws \RangeException
     * @throws \RuntimeException
     */
    public function setKey(string $value)
    {
        $size = mcrypt_get_key_size($this->cipher, MCRYPT_MODE_CBC);
        if (false === $size) {
            $message = 'Failed to get required key size';
            throw new \RuntimeException($message);
        }
        if ($size > strlen($value)) {
            $message = sprintf('Key must be at least %s characters long', $size);
            throw new \RangeException($message);
        }
        $this->keySize = $size;
        $this->key = $value;
        return $this;
    }
    /**
     * Used to add PKCS7 padding to the data being encrypt.
     *
     * @param string $data
     *
     * @return string
     */
    private function addPadding(string $data): string
    {
        /** @noinspection PhpMethodParametersCountMismatchInspection */
        $size = mcrypt_get_block_size($this->cipher, MCRYPT_MODE_CBC);
        $padding = $size - (strlen($data) % $size);
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
        $checksum += array_reduce(array_keys($this->queries), $func);
        $checksum += array_reduce($this->queries, $func);
        return sprintf('%X', $checksum);
    }
    /**
     * Converts 2 digit hex encoding bytes in a binary string.
     *
     * @param string $data
     *
     * @return string
     */
    private function getBytes(string $data): string
    {
        $results = '';
        foreach (str_split($data, 2) as $chunk) {
            $results .= chr(hexdec($chunk));
        }
        return $results;
    }
    /**
     * @return string
     */
    private function getInitVector(): string
    {
        return substr($this->initVector, 0, $this->ivSize);
    }
    /**
     * @return string
     */
    private function getKey(): string
    {
        return substr($this->key, 0, $this->keySize);
    }
    /**
     * Used to change a binary string one byte at a time to hex encoding string.
     *
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
     * Remove the PKCS7 padding from decrypted string.
     *
     * @param string $data
     *
     * @return string
     */
    private function removePadding(string $data): string
    {
        /** @noinspection PhpMethodParametersCountMismatchInspection */
        $size = mcrypt_get_block_size($this->cipher, MCRYPT_MODE_CBC) + 1;
        $padding = substr($data, -1);
        // Pads to next block so no more than $size chars.
        if ($size >= ord($padding)) {
            return rtrim($data, $padding);
        }
        return $data;
    }
    /**
     * Name for checksum value (unlikely to be used as arguments by user)
     *
     * @var string $checksumName
     */
    private $checksumName = "__$$";
    /**
     * @var string $cipher Which cipher is being used.
     */
    private $cipher = MCRYPT_DES;
    /**
     * Initialization vector use for encryption and decryption.
     *
     * Should be a binary string of the correct length for the cipher used.
     *
     * Originally was going to use array like from c# but string is easier to use direct in mcrypt.
     * $_keyBytes = [0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18];
     *
     * @internal string $keyBytes Original c# code called it _keyBytes and had a _keyString as well which was
     * confusing so renamed them both to match terms used in most encryption documentation.
     * @var string $initVector
     */
    private $initVector;
    /**
     * @var int $ivSize Length of initialization vector for current cipher.
     */
    private $ivSize;
    /**
     * Must be at least as long as the used cipher's minimum key size.
     *
     * @internal string $keyString Original c# code called it _keyString and had a _keyBytes as well which was
     * confusing so renamed them both to match terms used in PHP documentation.
     * @var string $key
     */
    private $key;
    /**
     * @var int $keySize Length of key for current cipher.
     */
    private $keySize;
    /**
     * Hold associate array of the query string keys and values.
     *
     * In the original c# code the class had to extend from another template class just to get something like this.
     * Makes you really appreciate how easy some things are in PHP.
     *
     * @var array $queries
     */
    private $queries = [];
}
