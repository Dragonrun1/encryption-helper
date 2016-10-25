<?php
declare(strict_types = 1);
/**
 * Created by PhpStorm.
 * User: Dragonaire
 * Date: 10/24/2016
 * Time: 3:47 PM
 */
require_once __DIR__ . '/src/EncryptionHelper.php';
$encryptedData = 'F7EBC908B106D4282FA705D0EED915DBE002774B1A152DCC';
print '$encryptedData = ' . $encryptedData . PHP_EOL;
$eh = new \EncryptionHelper\EncryptionHelper($encryptedData);
$toString = $eh . '';
print '$toString = ' . $toString . PHP_EOL;
$encrypted = $eh->encrypt($toString);
print '$encrypted = ' . $encrypted . PHP_EOL;
if ($encrypted === $encryptedData) {
    print 'Good, the encryption worked right.' . PHP_EOL;
} else {
    print 'Sad, the encryption did not work right.' . PHP_EOL;
}
$decrypted = $eh->decrypt($encrypted);
print '$decrypted = ' . $decrypted . PHP_EOL;
if ($decrypted === $toString) {
    print 'Great! Got back what we started with.';
} else {
    print 'Oops! Did not get back what we started with.';
}
