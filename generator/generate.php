<?php
/**
 * @author Lukas Reschke <lukas@owncloud.com>
 * @author Tom Needham <tom@owncloud.com>
 *
 * @copyright Copyright (c) 2015, ownCloud, Inc.
 * @license AGPL-3.0
 *
 * This code is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License, version 3,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License, version 3,
 * along with this program.  If not, see <http://www.gnu.org/licenses/>
 *
 */

date_default_timezone_set('Europe/Zurich');
$components = [
    'server',
    'desktop',
];
$advisorySideBar = '';

foreach($components as $component) {
    echo "… Iterating $component …\n";
    $componentBugs = [];

    $dir = new DirectoryIterator(__DIR__ . '/../' . $component);
    foreach ($dir as $fileinfo) {
        if (!$fileinfo->isDot()) {
            echo "Processing $fileinfo \n";

            $content = file_get_contents('./template.php');
            $advisory = json_decode(file_get_contents($fileinfo->getRealPath()), true);


            $content = str_replace('~~TITLE~~', $advisory['Title'], $content);
            $content = str_replace('~~IDENTIFIER~~',  str_replace('c-sa', 'C-SA', substr($fileinfo, 0, -5)), $content);
            $content = str_replace('~~DATE~~', date('jS F o', $advisory['Timestamp']), $content);

            $risk = $advisory['Risk'];
            switch ($risk) {
                case 1:
                    $risk = 'Low';
                    break;
                case 2:
                    $risk = 'Medium';
                    break;
                case 3:
                    $risk = 'High';
                    break;

            }
            $content = str_replace('~~LEVEL~~', $risk, $content);

            $cwe = '';
            if(isset($advisory['CWE'])) {
                $cwe = '<p>CWE: <a href="https://cwe.mitre.org/data/definitions/'.$advisory['CWE']['id'].'.html">'.$advisory['CWE']['name'] . ' (CWE-'.$advisory['CWE']['id'].')</a></p>';

            }
            $content = str_replace('~~CWE~~', $cwe, $content);

            $cvss = '';
            if(isset($advisory['CVSS2'])) {
                $cvss = '<p>CVSS v2 Base Score: '.$advisory['CVSS2']['score'].' (<a href="https://nvd.nist.gov/cvss.cfm?calculator&version=2&vector=('.$advisory['CVSS2']['vector'].')">'.$advisory['CVSS2']['vector'].'</a>)</p>';
            }
            $content = str_replace('~~CVSS2~~', $cvss, $content);

            $content = str_replace('~~DESCRIPTION~~', $advisory['Description'], $content);

            $affectedVersions = '';
            foreach($advisory['Affected'] as $affected) {
                $operator = isset($affected['Operator']) ? $affected['Operator'].' ' : '';
                $affectedVersions .= '<li>ownCloud '. ucfirst($component). ' ' . htmlentities($operator).'<strong>'.$affected['Version'].'</strong> ('.$affected['CVE'].')</li>';
                $componentBugs[$affected['Version']][substr($fileinfo, 0, -5)] = $advisory['Title'];
            }
            $content = str_replace('~~AFFECTEDVERSIONS~~', $affectedVersions, $content);

            if(isset($advisory['ActionTaken'])) {
                $actionTaken = $advisory['ActionTaken'];
            } else {
                $actionTaken = $advisory['Resolution'];
            }
            $content = str_replace('~~ACTION~~', $actionTaken, $content);

            $acknowledgments = '';
            if(isset($advisory['Acknowledgment'])) {
                foreach($advisory['Acknowledgment'] as $acknowledgment) {
                    $company = isset($acknowledgment['Company']) ? $acknowledgment['Company'] : '';
                    $mail = isset($acknowledgment['Mail']) ? $acknowledgment['Mail'] : '';
                    $reason = isset($acknowledgment['Reason']) ? $acknowledgment['Reason']: '';
                    $acknowledgments .= '<li>'.$acknowledgment['Name'].' - '.$company.' ('.$mail.') - '.$reason.'</li>';
                }
            }
            $content = str_replace('~~ACKNOWLEDGMENTS~~', $acknowledgments, $content);

            file_put_contents('./out/' . substr($fileinfo, 0, -5) . '.php', $content);

            echo "Finished $fileinfo\n";
        }
    }

    // Create advisory part files for complete overview
    uksort($componentBugs, 'version_compare');
    $componentBugs = array_reverse($componentBugs);
    $componentList = '';
    foreach($componentBugs as $version => $bug) {
        $componentList .= "<p>Version $version</p>";
        foreach($bug as $identifier => $title) {
            $componentList .= "<a href=\"/security/advisory?id=$identifier\">$title</a><br>";
        }
    }
    file_put_contents("./out/$component-list-part.php", $componentList);
    echo "Created component list\n";

    // Create sidebar with bugs from the latest version
    foreach($componentBugs as $version => $bug) {
        $advisorySideBar .= '<p>ownCloud ' . ucfirst($component) . ' ' . $version .'</p>';
        foreach($bug as $key => $title) {
            $advisorySideBar .= '<a href="/security/advisory?id='.$key.'">'.$title.'</a><br/>';
        }
        break;
    }


}

file_put_contents('./out/advisory-side.php', $advisorySideBar);
echo "Created advisory side bar\n";
