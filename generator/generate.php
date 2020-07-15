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

date_default_timezone_set('Europe/Berlin');
$components = [
    'server' => 'Server',
    'desktop' => 'Desktop Client',
    'android' => 'Android App',
    'ios' => 'iOS App',
    'calendar' => 'Calendar App',
    'circles' => 'Circles App',
    'contacts' => 'Contacts App',
    'deck' => 'Deck App',
    'groupfolders' => 'Groupfolders App',
    'mail' => 'Mail App',
    'talk' => 'Talk App',
    'preferred_providers' => 'Preferred providers',
    'lookup-server' => 'Lookup server',
];
$allBugs = [];

$dir = new DirectoryIterator(__DIR__ . '/out');
foreach ($dir as $fileinfo) {
    if ($fileinfo->isDot() || $fileinfo->getFilename() === '.gitkeep') {
        continue;
    }

    unlink($fileinfo->getRealPath());
}

foreach($components as $component => $componentName) {
    echo "… Iterating $component …\n";
    $componentBugs = [];

    $dir = new DirectoryIterator(__DIR__ . '/../' . $component);
    foreach ($dir as $fileinfo) {
        if (!$fileinfo->isDot() && $fileinfo->getFilename() !== '.gitkeep') {
            echo "Processing $fileinfo \n";

            $content = file_get_contents('./template.php');
            $advisory = json_decode(file_get_contents($fileinfo->getRealPath()), true);

            $content = str_replace(
                ['~~TITLE~~', '~~IDENTIFIER~~', '~~DATE~~'],
                [$advisory['Title'], str_replace('nc-sa', 'NC-SA', substr($fileinfo, 0, -5)), date('jS F o', $advisory['Timestamp'])],
                $content
            );

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
                $cwe = sprintf("<p>CWE: <a href=\"https://cwe.mitre.org/data/definitions/%s.html\">%s (CWE-%s)</a></p>", $advisory['CWE']['id'], $advisory['CWE']['name'], $advisory['CWE']['id']);

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
            $content = str_replace(
                ['~~CVSS~~', '~~DESCRIPTION~~'],
                [$cvss, $advisory['Description']],
                $content
            );

            $affectedVersions = '';
            foreach($advisory['Affected'] as $affected) {
                $operator = isset($affected['Operator']) ? $affected['Operator'] . ' ' : '';
                $affectedVersions .= sprintf("<li>Nextcloud %s %s<strong>%s</strong> (%s)</li>\n", ucfirst($component), htmlentities($operator), $affected['Version'], $affected['CVE']);
                if(isset($affected['Commits'])) {
                    $affectedVersions .= "<ul>\n";
                    $commitsToList = count($affected['Commits']);
                    foreach($affected['Commits'] as $commit) {
                        [$repository, $commit] = explode('/', $commit);
                        $affectedVersions .= sprintf("<li><a href=\"https://github.com/nextcloud/%s/commit/%s\">%s/%s</a></li>\n", $repository, $commit, $repository, $commit);
                    }
                    $affectedVersions .= "</ul>\n";
                }
                $componentBugs[$affected['Version']][substr($fileinfo, 0, -5)] = $advisory['Title'];
            }
            $content = str_replace('~~AFFECTEDVERSIONS~~', $affectedVersions, $content);

            $actionTaken = $advisory['ActionTaken'] ?? 'The error has been fixed.';
            $resolution = $advisory['Resolution'] ?? '';
            $content = str_replace(
                ['~~ACTION~~', '~~RESOLUTION~~'],
                [$actionTaken, $resolution],
                $content
            );

            $acknowledgments = '';
            if (isset($advisory['Acknowledgment'])) {
                foreach ($advisory['Acknowledgment'] as $acknowledgment) {
                    $company = $acknowledgment['Company'] ?? '';
                    $mail = $acknowledgment['Mail'] ?? '';
                    $reason = $acknowledgment['Reason'] ?? '';
                    $website = $acknowledgment['Website'] ?? '';
                    $acknowledgments .= '<li>';
                    if ($website) {
                        $acknowledgments .= '<a href="'.$website.'" target="_blank" rel="noreferrer">';
                    }
                    $acknowledgments .= $acknowledgment['Name'];
                    if ($company !== '') {
                        $acknowledgments .= ' - '.$company;
                    }
                    if ($mail !== '') {
                        $acknowledgments .= ' ('.$mail.')';
                    }
                    $acknowledgments .= ' - '.$reason;
                    if ($website) {
                        $acknowledgments .= '</a>';
                    }
                    $acknowledgments .= '</li>';
                }
            }
            $content = str_replace('~~ACKNOWLEDGMENTS~~', $acknowledgments, $content);

            if (file_exists('./out/' . substr($fileinfo, 0, -5) . '.php')) {
                throw new Exception('Duplicate identifier: ' . substr($fileinfo, 0, -5));
            }
            file_put_contents('./out/' . substr($fileinfo, 0, -5) . '.php', $content);

            echo "Finished $fileinfo\n";
        }
    }

    // Create complete overview list
    uksort($componentBugs, 'version_compare');
    $componentBugs = array_reverse($componentBugs);

    $allBugs[$component] = $componentBugs;
}

// Create RSS feed & overview page
$identifiersDone = [];
$rssEntries = [];
$listEntries = [];
$rss = '<?xml version="1.0" encoding="UTF-8" ?>
<rss version="2.0" xmlns:atom="http://www.w3.org/2005/Atom">
<channel>
 <title>Nextcloud Security Advisories RSS Feed</title>
 <link>https://nextcloud.com/security/advisories/</link>
 <description>The Nextcloud security advisories as a RSS feed</description>
 <ttl>1800</ttl>';
foreach ($allBugs as $category => $list) {
    foreach  ($list as $advisories) {
        foreach ($advisories as $identifier => $title) {
            if (!isset($identifiersDone[$identifier])) {
                $identifiersDone[$identifier] = 'true';
                $advisoryContent = json_decode(file_get_contents(__DIR__ . '/../' . strtolower($category) . '/' . $identifier . '.json'), true);
                if (!isset($components[strtolower($category)])) {
                    throw new Exception('Unknown category: ' . $category);
                }
                $categoryText = $components[strtolower($category)];
                $identifier = str_replace('c-sa', 'C-SA', substr($identifier, 0));
                $description = htmlentities($advisoryContent['Description'] . '<br/><hr/><p><strong><a href="https://nextcloud.com/security/advisory/?id=' . $identifier . '">For more information please consult the official advisory.</a></strong></p>');
                $originalTitle = $title;
                $title = htmlentities($categoryText . ': ' . $title . ' (' . ucfirst($identifier) . ')');
                $date = date('r', $advisoryContent['Timestamp']);
                $rssEntry = "<item>
  <title>$title</title>
  <description>$description</description>
  <link>https://nextcloud.com/security/advisory/?id=$identifier</link>
  <guid isPermaLink=\"true\">https://nextcloud.com/security/advisory/?id=$identifier</guid>
  <pubDate>$date</pubDate>
 </item>";
                $rssEntries[$identifier] = $rssEntry;

                $identifier = ucfirst($identifier);
                // overview page
                foreach ($advisoryContent['Affected'] as $key => $value) {
                    if ($categoryText === 'Server') {
                        $categoryText = 'Nextcloud Server';
                    }
                    $version = $value['Version'];
                    $dateTime = date('Y-m-d', $advisoryContent['Timestamp']);
                    $listEntry = "<li><a href=\"/security/advisory/?id=$identifier\">" . htmlentities($originalTitle) . " ($identifier)</a> $dateTime</li>";

                    $year = substr($identifier, 6, 4);
                    $listId = $categoryText . ' ' . $version;
                    if (!isset($listEntries[$year])) {
                        $listEntries[$year] = [];
                    }
                    if (!isset($listEntries[$year][$dateTime])) {
                        $listEntries[$year][$dateTime] = [];
                    }
                    if (!isset($listEntries[$year][$dateTime][$listId])) {
                        $listEntries[$year][$dateTime][$listId] = [];
                    }
                    $listEntries[$year][$dateTime][$listId][] = $listEntry;
                    rsort($listEntries[$year][$dateTime][$listId]);
                }
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

$fullList = '';

foreach ($listEntries as $year => $dateList) {

    $fullList .= "<hr>\n\n";
    $fullList .= "<h2>$year</h2>\n\n";

    krsort($dateList); // sort descending by date
    foreach ($dateList as $key => $sublist) {
        foreach ($sublist as $title => $entries) {
            $fullList .= "<h3>$title</h3>\n<ul>\n\t";
            $fullList .= implode("\n\t", $entries);
            $fullList .= "\n</ul>\n\n";
        }
    }
}

file_put_contents('./out/full-list.php', $fullList);
echo "Created full list\n";

