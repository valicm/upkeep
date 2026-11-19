<?php
/*
 * Runs the real statusAction() of OPNsense's FirmwareController (core, stable/26.7) outside a
 * firewall. Only the two things the action reaches out to are replaced: the configd backend
 * ("firmware product" answers with the JSON that scripts/firmware/product.php prints) and the
 * request object. The result is encoded the way Mvc/Response.php sends it.
 *
 * usage: harness.php FirmwareController.php core-metadata.json check.json|- [mirror] [license.json]
 */
namespace OPNsense\Base {
    class ApiMutableModelControllerBase
    {
        public $request;
    }
}

namespace OPNsense\Core {
    class Backend
    {
        public static $product = '';
        public function configdRun($event, $detach = false)
        {
            return $event === 'firmware product' ? self::$product : '';
        }
    }
    class Config
    {
    }
    class SanitizeFilter
    {
    }
    class Shell
    {
    }
}

namespace {
    if (!function_exists('gettext')) {
        function gettext($s)
        {
            return $s;
        }
    }

    class FixtureRequest
    {
        public function isPost()
        {
            return false;
        }
    }

    require $argv[1];

    /* what product.php does, with the shell commands' answers passed in */
    $ret = json_decode(file_get_contents($argv[2]), true);
    $extra = json_decode(file_get_contents($argv[3]), true);
    $ret['product_latest'] = $extra['product_latest'];
    $ret['product_mirror'] = preg_replace(
        '/\/[a-z0-9]{8}(-[a-z0-9]{4}){3}-[a-z0-9]{12}\//i',
        '/${SUBSCRIPTION}/',
        $extra['mirror']
    );
    $ret['product_time'] = $extra['product_time'];
    $ret['product_log'] = $extra['product_log'];
    $ret['product_repos'] = $extra['product_repos'];
    $ret['product_check'] = $argv[4] === '-' ? null : json_decode(file_get_contents($argv[4]), true);
    if ($argv[4] !== '-' && $ret['product_check'] === null) {
        fwrite(STDERR, "check file is not valid JSON\n");
        exit(1);
    }
    $ret['product_license'] = [];
    foreach ($extra['license'] ?? [] as $key => $val) {
        $ret['product_license'][$key] = $val;
    }
    ksort($ret);
    \OPNsense\Core\Backend::$product = json_encode($ret, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . PHP_EOL;

    $controller = new \OPNsense\Core\Api\FirmwareController();
    $controller->request = new FixtureRequest();
    echo json_encode($controller->statusAction(), JSON_INVALID_UTF8_IGNORE);
}
