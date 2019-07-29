<?php
namespace \4cm\crypto;

class crypto
{
    private $keypath;
    private $content;
    private $direction;

    function __construct($keypath, $content='', $direction='') {
        //
        $this->keypath = $keypath;
        $this->content = $content;
        $this->direction = $direction;
        //
    }

    /**
     * @usage: $EncryptedContent = (new crypto($keyPath, $Content, 'e'))->crypto();
     * @usage: $Content = (new crypto($keyPath, $EncryptedContent, 'd'))->crypto();
     * @return bool|string
     * @throws Exception
     */
    public function crypto()
    {
        //
        //
        ///////////////////////////////////////////////////////////////////////
        //  Sodium Cryptography Extensions Is Required
        ///////////////////////////////////////////////////////////////////////
        //
        if (!extension_loaded('sodium')) {
            //
            throw new Exception('crypto requires the Sodium Cryptography Extensions be installed on your server. Please visit https://www.php.net/manual/en/sodium.installation.php');
            //
        }
        //
        //
        ///////////////////////////////////////////////////////////////////////
        //   Validate Key Exists
        ///////////////////////////////////////////////////////////////////////
        //
        if (strlen($this->keypath) <= PHP_MAXPATHLEN && file_exists($this->keypath)) {
            //
            $getKeyData = file_get_contents($this->keypath);
            //
            if ( isset($getKeyData) && !empty($getKeyData) ) {
                //
                $keyData = $getKeyData;
                //
            }
            else {
                //
                throw new Exception('crypto::crypto: Key File Did Not Load. Check that the file exists and can be read.');
                //
            }
            //
        }
        else {
            //
            throw new Exception('crypto::crypto: Key Does Not Exist');
            //
        }
        //
        //
        ///////////////////////////////////////////////////////////////////////
        //  Encrypt
        ///////////////////////////////////////////////////////////////////////
        //
        if ( $this->direction === 'e' ) {
            //
            $nonce = random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
            $cipher = base64_encode($nonce.sodium_crypto_secretbox($this->content, $nonce, $keyData));
            //
            sodium_memzero($this->content);
            sodium_memzero($keyData);
            //
            return $cipher;
            //
        }
        //
        //
        ///////////////////////////////////////////////////////////////////////
        //   Decrypt
        ///////////////////////////////////////////////////////////////////////
        //
        elseif ( $this->direction === 'd' ) {
            //
            $decoded = base64_decode($this->content);
            //
            if ($decoded === false) {
                //
                throw new Exception('crypto::crypto: Encoding Failure');
                //
            }
            if (mb_strlen($decoded, '8bit') < (SODIUM_CRYPTO_SECRETBOX_NONCEBYTES + SODIUM_CRYPTO_SECRETBOX_MACBYTES)) {
                //
                throw new Exception('crypto::crypto: Invalid Content Provided');
                //
            }
            //
            $nonce = mb_substr($decoded, 0, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES, '8bit');
            $cipher = mb_substr($decoded, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES, null, '8bit');
            $plain = sodium_crypto_secretbox_open($cipher,$nonce,$keyData);
            //
            if ($plain === false) {
                //
                throw new Exception('crypto::crypto: Message Tampering');
                //
            }
            //
            sodium_memzero($cipher);
            sodium_memzero($keyData);
            //
            return $plain;
            //
        }
        else {
            //
            return false;
            //
        }
        //
    }

    /**
     * @usage: (new crypto($keyPath))->generateKey();
     * @return bool
     * @throws Exception
     */
    public function generateKey()
    {
        //
        //
        ///////////////////////////////////////////////////////////////////////
        //   Does Key Already Exist
        ///////////////////////////////////////////////////////////////////////
        //
        if (strlen($this->keypath) <= PHP_MAXPATHLEN && file_exists($this->keypath)) {
            //
            return true;
            //
        }
        //
        //
        ///////////////////////////////////////////////////////////////////////
        //  Generate Key Bytes
        ///////////////////////////////////////////////////////////////////////
        //
        $keyData = random_bytes(SODIUM_CRYPTO_SECRETBOX_KEYBYTES);
        //
        //
        ///////////////////////////////////////////////////////////////////////
        //  Save Key Data
        ///////////////////////////////////////////////////////////////////////
        //
        file_put_contents($this->keypath, $keyData);
        //
        //
        ///////////////////////////////////////////////////////////////////////
        //   Verify file was created
        ///////////////////////////////////////////////////////////////////////
        //
        if (strlen($this->keypath) <= PHP_MAXPATHLEN && file_exists($this->keypath)) {
            //
            return true;
            //
        }
        else {
            //
            throw new Exception('crypto::generateKey: Key Failed To Be Generated');
            //
        }
        //
    }
    //
}
