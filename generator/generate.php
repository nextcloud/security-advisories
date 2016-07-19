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
$allBugs = [];

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
            $content = str_replace('~~IDENTIFIER~~',  str_replace('nc-sa', 'NC-SA', substr($fileinfo, 0, -5)), $content);
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

            $hackerOne = '';
            if(isset($advisory['HackerOne'])) {
                $hackerOne = '<p>HackerOne report: <a href="https://hackerone.com/reports/'.$advisory['HackerOne'].'">'.$advisory['HackerOne'] .'</a></p>';

            }
            $content = str_replace('~~HackerOne~~', $hackerOne, $content);

            $cvss = '';
            if(isset($advisory['CVSS2'])) {
                $cvss = '<p>CVSS v2 Base Score: '.$advisory['CVSS2']['score'].' (<a href="https://nvd.nist.gov/cvss.cfm?calculator&version=2&vector=('.$advisory['CVSS2']['vector'].')">'.$advisory['CVSS2']['vector'].'</a>)</p>';
            }
            if(isset($advisory['CVSS3'])) {
                $cvss = '<p>CVSS v3 Base Score: '.$advisory['CVSS3']['score'].' (<a href="https://www.first.org/cvss/calculator/3.0#CVSS:3.0/'.$advisory['CVSS3']['vector'].'">'.$advisory['CVSS3']['vector'].'</a>)</p>';
            }
            $content = str_replace('~~CVSS~~', $cvss, $content);

            $content = str_replace('~~DESCRIPTION~~', str_replace("</p>", "</p>\n", $advisory['Description']), $content);

            $affectedVersions = '';
            foreach($advisory['Affected'] as $affected) {
                $operator = isset($affected['Operator']) ? $affected['Operator'].' ' : '';
                $affectedVersions .= "<li>Nextcloud ". ucfirst($component). " " . htmlentities($operator)."<strong>".$affected["Version"]."</strong> (".$affected["CVE"].")</li>\n";
                if(isset($affected['Commits'])) {
                    $affectedVersions .= "<ul>\n";
                    $commitsToList = count($affected['Commits']);
                    foreach($affected['Commits'] as $commit) {

                        $repository = explode('/', $commit)[0];
                        $commit = explode('/', $commit)[1];

                        $affectedVersions .= "<li><a href=\"https://github.com/nextcloud/".$repository."/commit/".$commit."\">".$repository."/".$commit."</a></li>\n";
                    }
                    $affectedVersions .= "</ul>\n";
                }
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
                    $website = isset($acknowledgment['Website']) ? $acknowledgment['Website']: '';
                    $acknowledgments .= '<li>';
                    if($website) {
                        $acknowledgments .= '<a href="'.$website.'" target="_blank" rel="noreferrer">';
                    }
                    $acknowledgments .= $acknowledgment['Name'];
                    if($company !== '') {
                        $acknowledgments .= ' - '.$company;
                    }
                    if($mail !== '') {
                        $acknowledgments .= ' ('.$mail.')';
                    }
                    $acknowledgments .= ' - '.$reason;
                    if($website) {
                        $acknowledgments .= '</a>';
                    }
                    $acknowledgments .= '</li>';
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
        $advisorySideBar .= "<br/><p>Nextcloud " . $component . " " . $version ."</p>\n";
        foreach($bug as $key => $title) {
            $advisorySideBar .= "<a href=\"/security/advisory?id=".$key."\">".$title."</a><br/>\n";
        }
        break;
    }

    $allBugs[$component] = $componentBugs;
}

// Create RSS feed
$identifiersDone = [];
$rssEntries = [];
$rss = '<?xml version="1.0" encoding="UTF-8" ?>
<rss version="2.0" xmlns:atom="http://www.w3.org/2005/Atom">
<channel>
 <title>Nextcloud Security Advisories RSS Feed</title>
 <link>https://nextcloud.com/security/advisories/</link>
 <description>The Nextcloud security advisories as a RSS feed</description>
 <ttl>1800</ttl>';
foreach($allBugs as $category => $advisories) {
    foreach($advisories as $advisories) {
        foreach ($advisories as $identifier => $title) {
            if (!isset($identifiersDone[$identifier])) {
                $identifiersDone[$identifier] = 'true';
                $advisoryContent = json_decode(file_get_contents(__DIR__ . '/../' . strtolower($category) . '/' . $identifier . '.json'), true);
                switch (strtolower($category)) {
                    case 'mobile':
                        $categoryText = 'Mobile App';
                        break;
                    case 'desktop':
                        $categoryText = 'Desktop Client';
                        break;
                    case 'server':
                        $categoryText = 'Server';
                        break;
                    default:
                        throw new Exception('Should never happen');
                        break;
                }
                $identifier = str_replace('c-sa', 'C-SA', substr($identifier, 0));
                $description = htmlentities($advisoryContent['Description'] . '<br/><hr/><p><strong><a href="https://nextcloud.com/security/advisory/?id=' . $identifier . '">For more information please consult the official advisory.</a></strong></p>');
                $title = htmlentities($categoryText . ': ' . $title . ' (' . $identifier . ')');
                $date = date('r', $advisoryContent['Timestamp']);
                $rssEntry = "<item>
  <title>$title</title>
  <description>$description</description>
  <link>https://nextcloud.com/security/advisory/?id=$identifier</link>
  <guid isPermaLink=\"true\">https://nextcloud.com/security/advisory/?id=$identifier</guid>
  <pubDate>$date</pubDate>
 </item>";
                $rssEntries[$identifier] = $rssEntry;
            }
        }
    }
}
ksort($rssEntries);
$rssEntries = array_reverse($rssEntries);
foreach($rssEntries as $entry) {
    $rss.=$entry;
}
$rss .= '
</channel>
</rss>';

file_put_contents('./out/advisories.rss', $rss);
echo "Created RSS feed\n";

file_put_contents('./out/advisory-side.php', $advisorySideBar);
echo "Created advisory side bar\n";
