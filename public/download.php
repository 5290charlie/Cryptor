<?php

$strBaseDir = dirname(__FILE__);

require $strBaseDir . '/../lib/Cryptor.inc';

$objCryptor = new Cryptor(true);

if (isset($_POST) && isset($_POST['do']) && isset($_POST['key']) && $_POST['key'] != '') {
	if ($_FILES['file']['error'] > 0) {
		echo 'Error: ' . $_FILES['file']['error'];
	} else {
		$strKey = $_POST['key'];
		$strAction = $_POST['do'];
		$strFileTmp = $_FILES['file']['tmp_name'];
		$strFileEnc = $strFileTmp . '.enc';
		$strFileDec = $strFileTmp . '.dec';
		$arrFileRes = [
			'encrypt' => $strFileEnc,
			'decrypt' => $strFileDec
		];

		if (!isset($arrFileRes[$strAction])) {
			die('invalid action: "' . $strAction . '"');
		}

		if ($strAction == 'encrypt' && (!isset($_POST['confirm']) || $_POST['key'] != $_POST['confirm'])) {
			die('invalid or mismatching keys. please try again.');
		}

		if (isset($_POST['saveas']) && $_POST['saveas'] != '') {
			$strFilename = $_POST['saveas'];
		} else {
			$strFilename = $strAction . 'ed-' . time() . '-' . $_FILES['file']['name'];
    }

		$objCryptor->run([
			'cryptor-web',
			$strAction,
			$strFileTmp,
			$arrFileRes[$strAction],
			$strKey
		]);

		header('Content-Description: File Transfer');
		header('Content-Type: application/octet-stream');
		header('Content-Disposition: attachment; filename=' . $strFilename);
		header('Content-Transfer-Encoding: binary');
		header('Expires: 0');
		header('Cache-Control: must-revalidate, post-check=0, pre-check=0');

		echo file_get_contents($arrFileRes[$strAction]);
	}
} else {
	header('Location: index.php');
}

exit;
