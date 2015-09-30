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
    'mobile',
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

            $content = str_replace('~~DESCRIPTION~~', str_replace("</p>", "</p>\n", $advisory['Description']), $content);

            $affectedVersions = '';
            foreach($advisory['Affected'] as $affected) {
                $operator = isset($affected['Operator']) ? $affected['Operator'].' ' : '';
                $affectedVersions .= "<li>ownCloud ". ucfirst($component). " " . htmlentities($operator)."<strong>".$affected["Version"]."</strong> (".$affected["CVE"].")</li>\n";
                $componentBugs[$affected['Version']][substr($fileinfo, 0, -5)] = $advisory['Title'];
            }
            $content = str_replace('~~AFFECTEDVERSIONS~~', $affectedVersions, $content);

            if(isset($advisory['ActionTaken'])) {
                $actionTaken = $advisory['ActionTaken'];
            } else {
                $actionTaken = $advisory['Resolution'];
            }
            $content = str_replace('~~ACTION~~',  str_replace("</p>", "</p>\n", $actionTaken), $content);

            $acknowledgments = '';
            if(isset($advisory['Acknowledgment'])) {
                foreach($advisory['Acknowledgment'] as $acknowledgment) {
                    $company = isset($acknowledgment['Company']) ? $acknowledgment['Company'] : '';
                    $mail = isset($acknowledgment['Mail']) ? $acknowledgment['Mail'] : '';
                    $reason = isset($acknowledgment['Reason']) ? $acknowledgment['Reason']: '';
                    $acknowledgments .= '<li>'.$acknowledgment['Name'];
                    if($company !== '') {
                        $acknowledgments .= ' - '.$company;
                    }
                    if($mail !== '') {
                        $acknowledgments .= ' ('.$mail.')';
                    }
                    $acknowledgments .= ' - '.$reason.'</li>';
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
    $i = 0;
    foreach($componentBugs as $version => $bug) {
        if($i !== 0) {
            $componentList .= "<br/>";
        }
        $componentList .= "<p>Version $version</p>\n";
        foreach($bug as $identifier => $title) {
            $componentList .= "<a href=\"/security/advisory?id=$identifier\">$title</a><br>\n";
        }
        $i++;
    }
    file_put_contents("./out/$component-list-part.php", $componentList);
    echo "Created component list\n";

    // Create sidebar with bugs from the latest version
    $i = 0;
    foreach($componentBugs as $version => $bug) {
        if($i !== 0) {
            $advisorySideBar .= "<br/>";
        }
        $advisorySideBar .= "<p>ownCloud " . $component . " " . $version ."</p>\n";
        foreach($bug as $key => $title) {
            $advisorySideBar .= "<a href=\"/security/advisory?id=".$key."\">".$title."</a><br/>\n";
        }
        $i++;
        break;
    }


}

file_put_contents('./out/advisory-side.php', $advisorySideBar);
echo "Created advisory side bar\n";
