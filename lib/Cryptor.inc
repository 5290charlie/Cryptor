<?php

define('ASCII_MIN', 8);
define('ASCII_MAX', 224);
define('BASE64_MIN', 47);
define('BASE64_MAX', 122);
define('CHUNK_SIZE', 1024);
define('STAMP_SIZE', 12);

/**
 * Cryptor
 */
class Cryptor {
  public $blnForce = false;
  public $blnOutput = true;

	private $arrActions = [
		'e' => 'encrypt',
		'd' => 'decrypt'
	];

	private $strScriptName = __FILE__;
	private $strKey = '';
	private $strAction = '';
	private $strInputFile = '';
	private $strOutputFile = '';
	private $strSignature = '';
  private $intTestNumber = 1;

  public function __construct($blnSilent = false) {

    if ($blnSilent === true) {
      $this->blnForce = true;
      $this->blnOutput = false;
    } else {
      $mixDebugExist = trim(`ls /tmp/debug-* | wc -l`);

      if (is_numeric($mixDebugExist) && $mixDebugExist > 0) {
        if ($this->confirm('Purge existing debug file(s)?')) {
          $this->msg('Purging existing debug files...');
          exec('rm /tmp/debug-*');
        }
      }
    }
  }

  private function init($arrArgs) {
    $this->strScriptName = $arrArgs[0];
		$this->strAction = trim(strtolower($arrArgs[1]));
		$this->strInputFile = $arrArgs[2];

		if (isset($arrArgs[3])) {
			$this->strOutputFile = $arrArgs[3];
		}

		if (isset($arrArgs[4])) {
			$this->strKey = $arrArgs[4];
		}

    if (isset($arrArgs[5]) && is_numeric($arrArgs[5])) {
      $this->intTestNumber = $arrArgs[5];
    }

		if (!$this->validate()) {
			$this->usage();
			die();
    }
  }

	public function run($arrArgs) {
    $this->init($arrArgs);

		if ($this->strKey != '') {
			$strKey = md5($this->strKey);
		} else {
			$strKey  = md5($this->readString('Enter key: '));
		}

    $strFileSalt = md5(trim(file_get_contents(__FILE__)));
    $strKeyHash = md5(trim($strKey));

		$strSign = md5($strKeyHash . $strFileSalt);

    $arrDebug = [];
		$strBuffer = '';
		$intAltMin = BASE64_MIN - ASCII_MIN;
		$intAltMax = ASCII_MAX - BASE64_MAX - ASCII_MIN;
		$srmInFile = fopen($this->strInputFile, 'r');

		$intPosition = 0;

    $arrDebug = [
      'test_num' => $this->intTestNumber,
      'alt_min' => $intAltMin,
      'action' => $this->strAction,
      'key_orig' => $strKey,
      'key_hash' => $strKeyHash,
      'file_salt' => $strFileSalt,
      'sign' => $strSign,
    ];

		switch ($this->strAction) {
			case 'encrypt':
				$srmOutFile  = fopen($this->strOutputFile, 'w');
				$intFileSize = filesize($this->strInputFile) > 0 ? filesize($this->strInputFile) : 1;
				$intNumChunk = ceil($intFileSize / CHUNK_SIZE);

				$intStamp = substr((microtime(true) * 10000), (-1 * STAMP_SIZE));

				fwrite($srmOutFile, $strSign . $intStamp . PHP_EOL);

				$strKey = md5($strKey . $intStamp);
        $intKey = $this->getKeyVal($strKey);
        $intMod = fmod($intKey * $intStamp, $intAltMax);
        $intMod += fmod($intStamp, ($intAltMax - $intMod));
        $intMod += ASCII_MIN;

        $arrDebug = array_merge($arrDebug, [
          'stamp' => $intStamp,
          'mod' => $intMod,
          'key' => $strKey,
        ]);

				while (!feof($srmInFile)) {
					$strOutput = '';
					$strBuffer = fread($srmInFile, CHUNK_SIZE);

					foreach (str_split(base64_encode($strBuffer)) as $intIndex => $strChar) {
						$intChar = ord($strChar);
						$intChar -= $intAltMin;
            $intChar += $intMod;
            $strOutput .= chr($intChar);
					}

					$strOutput .= PHP_EOL;

					fwrite($srmOutFile, $strOutput);

					$intPosition++;
					$intPercent = round( ( $intPosition / $intNumChunk ) * 100, 0 );
					$this->msg("Encrypting [$intPercent%]", true);
				}

				fclose($srmOutFile);
				fclose($srmInFile);

				break;
			case 'decrypt':
				$intNumLines = (int) `wc -l < {$this->strInputFile}`;
				$strInfoLine = trim(fgets($srmInFile));
				$intNumLines--;

				if (substr($strInfoLine, 0, strlen($strSign)) != $strSign) {
					$this->error("Invalid signature!");
				} else {
					$intStamp = substr($strInfoLine, strlen($strSign));

					$strKey = md5($strKey . $intStamp);
          $intKey = $this->getKeyVal($strKey);
          $intMod = fmod($intKey * $intStamp, $intAltMax);
          $intMod += fmod($intStamp, ($intAltMax - $intMod));
          $intMod += ASCII_MIN;

					$srmOutFile  = fopen($this->strOutputFile, 'w');

          $arrDebug = array_merge($arrDebug, [
            'stamp' => $intStamp,
            'mod' => $intMod,
            'key' => $strKey,
          ]);

					while (!feof($srmInFile)) {
						$strOutput = '';
						$strLine = fgets($srmInFile);

						if ($strLine) {
							$strLine = rtrim($strLine, PHP_EOL);

							foreach (str_split($strLine) as $intIndex => $strChar) {
								$intChar = ord($strChar);
								$intChar += $intAltMin;
                $intChar -= $intMod;
								$strOutput .= chr($intChar);
							}

							fwrite($srmOutFile, base64_decode($strOutput));

							$intPosition++;
							$intPercent = round( ( $intPosition / $intNumLines ) * 100, 0 );
							$this->msg("Decrypting [$intPercent%]", true);
						}
					}
					fclose($srmOutFile);
				}

				fclose($srmInFile);

				break;
		}

    file_put_contents('/tmp/debug-' . basename($this->strInputFile), json_encode($arrDebug, JSON_PRETTY_PRINT), FILE_APPEND);

    if ($this->blnOutput) {
      echo PHP_EOL;
    }
	}

	private function getKeyVal($strKey) {
		$intKey = 0;
		$arrKey = str_split($strKey);

		foreach ($arrKey as $intIndex => $strKeyChar) {
			$intKey += ord($strKeyChar);
		}

		return $intKey;
	}

	private function validate() {
		if (isset($this->arrActions[$this->strAction])) {
			$this->strAction = $this->arrActions[$this->strAction];
		}

		if (!in_array($this->strAction, $this->arrActions)) {
			$this->error("Invalid <action>: '{$this->strAction}'!");
			return false;
		}

		if (!file_exists($this->strInputFile)) {
			$this->error("Input file: '{$this->strInputFile}' does not exist!");
			return false;
		}

		if ($this->strOutputFile == '') {
			$this->strOutputFile = $this->strInputFile . '.' . $this->strAction . 'ed';
			$this->msg("NOTICE: No output file specified. Saving to file: '{$this->strOutputFile}'");
		}

		if (file_exists($this->strOutputFile)) {
      if (!$this->blnForce) {
        $this->msg("WARNING: Output file: '{$this->strOutputFile}' already exists!");

        if (!$this->confirm('Overwrite this file?')) {
          return false;
        }
      }
		}

		return true;
	}

	private function confirm($strMsg = 'Are you sure?') {
    if ($this->blnForce) {
      return true;
    }

		$arrAnswers = [
			'y',
			'n',
			'yes',
			'no'
		];

		do {
			$this->msg($strMsg);
      $strYesNo = strtolower($this->readString('(y/n): '));
		} while (!in_array($strYesNo, $arrAnswers));

		return ($strYesNo == 'y' || $strYesNo == 'yes');
	}

	private function readString($strMsg = 'Enter value: ') {
		echo $strMsg;

		return trim(fgets(STDIN));
	}

	private function usage() {
		$this->msg("Usage: {$this->strScriptName} <action (encrypt|decrypt)> <input file> [<output file>]");
	}

	private function msg($strMsg, $blnReplace = false) {
    if ($this->blnOutput) {
      if ($blnReplace) {
  			echo "\r$strMsg";
  		} else {
  			echo "$strMsg" . PHP_EOL;
  		}
    }
	}

  private function error($strMsg) {
    if ($this->blnOutput) {
      $this->msg($strMsg);
    } else {
      throw new Exception($strMsg);
    }
  }
}
