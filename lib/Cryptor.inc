<?php

define('ASCII_MIN', 1);
define('ASCII_MAX', 255);
define('BASE64_MIN', 47);
define('BASE64_MAX', 122);
define('CHUNK_SIZE', 1024);
define('STAMP_SIZE', 12);

/**
 * Cryptor
 */
class Cryptor {
  public $blnForce = false;

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

		if (!$this->validate()) {
			$this->usage();
			die();
		}
  }

	public function run($arrArgs) {
    $this->init($arrArgs);

		if ($this->strKey != '') {
			$strKey = $this->strKey;
		} else {
			$strKey  = md5($this->readString('Enter key: '));
		}

		$strSign = md5(file_get_contents(__FILE__) . $strKey);

		$strBuffer = '';
		$intAltMin = BASE64_MIN - ASCII_MIN;
		$intAltMax = ASCII_MAX - (BASE64_MAX - ASCII_MIN);
		$srmInFile = fopen($this->strInputFile, 'r');

		$intPosition = 0;

		switch ($this->strAction) {
			case 'encrypt':
				$srmOutFile  = fopen($this->strOutputFile, 'w');
				$intFileSize = filesize($this->strInputFile) > 0 ? filesize($this->strInputFile) : 1;
				$intNumChunk = ceil($intFileSize / CHUNK_SIZE);

				$intStamp = substr((microtime(true) * 10000), (-1 * STAMP_SIZE));

				fwrite($srmOutFile, $strSign . $intStamp . PHP_EOL);

				$strKey = md5($strKey . $intStamp);
        $intKey = $this->getKeyVal($strKey);
        $intMod = $intKey % $intAltMax;

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
					$this->msg("Invalid signature!");
				} else {
					$intStamp = substr($strInfoLine, strlen($strSign));

					$strKey = md5($strKey . $intStamp);
          $intKey = $this->getKeyVal($strKey);
          $intMod = $intKey % $intAltMax;

					$srmOutFile  = fopen($this->strOutputFile, 'w');

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

		echo PHP_EOL;
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
			$this->msg("Invalid <action>: '{$this->strAction}'!");
			return false;
		}

		if (!file_exists($this->strInputFile)) {
			$this->msg("Input file: '{$this->strInputFile}' does not exist!");
			return false;
		}

		if ($this->strOutputFile == '') {
			$this->strOutputFile = $this->strInputFile . '.' . $this->strAction . 'ed';
			$this->msg("NOTICE: No output file specified. Saving to file: '{$this->strOutputFile}'");
		}

		if (file_exists($this->strOutputFile)) {
			$this->msg("WARNING: Output file: '{$this->strOutputFile}' already exists!");

			if (!$this->confirm('Overwrite this file?')) {
				return false;
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
			echo '(y/n): ';
			$strYesNo = trim(strtolower(fgets(STDIN)));
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
		if ($blnReplace) {
			echo "\r$strMsg";
		} else {
			echo "$strMsg" . PHP_EOL;
		}
	}
}
