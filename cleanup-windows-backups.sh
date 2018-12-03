
#!/bin/bash
# cleans up popular temporary/cache files 
# from copies of windows disks 
# Pass the path to clean as an argument

if [[ -z "$1" ]] ; then
           echo "usage $0 /some/path"
              exit
      fi
      cd $1 || exit 5
      TIMESTAMP=`date +"%Y-%m-%d_%H.%M.%S"`

      # list of app data files to delete
      cat << __EOF__ > /tmp/rm-list
///--------------------------------
/// cache files
///--------------------------------
/Mozilla/.*/Cache
/MicrosoftEdge/Cache
/Chrome/.*/Cache
/Default/Media Cache
/GoogleEarth/unified_cache
/AppData/Local/Temp
/MicrosoftEdge/.*/Cache
/Skype/.*/emo_cache
/Device Metadata/dmrccache$
/cache$
/INetCache$
/LocalCache$
/Package Cache$
/WebCache$
/OfficeFileCache$
/CryptnetUrlCache$
/AppCache$
/IECompatCache$
/WebServiceCache$
/IECompatUaCache$
///--------------------------------
/// logs in appdata
///--------------------------------
/logs$
/log$
///--------------------------------
/// windows system files in appdata
///--------------------------------
/AppData/Local/Microsoft/Windows$
/AppData/Local/Microsoft/Device Stage$
///--------------------------------
/// temporary dirs in appdata
///--------------------------------
/temp$
/temporary[^/]*$
__EOF__


echo "disk usage (in MBytes) before deletions"
df -m .

echo "Building list of dirs in AppData"
find -type d |grep -i '/AppData/' > /tmp/cleanup-appdatadirs

echo "Deleting files/dirs from AppData"
grep -f /tmp/rm-list /tmp/cleanup-appdatadirs > /tmp/cleanup-deleted-from-appdata
xargs -i rm -rf "{}" < /tmp/cleanup-deleted-from-appdata
echo "I've kept the list of files that were deleted at /tmp/cleanup-deleted-from-appdata"

echo "disk usage after deletions"
df -m .

echo deleting .tmp files and office temporary files
find -type f -iname '*.tmp' -delete
find -iname '~$*.xls?' -delete
find -iname '~$*.xls' -delete
find -iname '~$*.doc?' -delete
find -iname '~$*.doc' -delete
find -iname '~$*.ppt?' -delete
find -iname '~$*.ppt' -delete

echo "disk usage after deletions"
df -m .

echo "Creating list of dirs that MAY BE cache or temp dirs"
(
#locate dirs which *may* be cache dirs
echo "# files bellow MAY BE cache dirs "
cat /tmp/cleanup-appdatadirs|grep -i cache|sed -e 's/\(cache[^/]*\).*$/\1/I'|uniq
# if you pipe the result via this command it will only print dirs with more than 50MB
# |xargs -i du -sm "{}"|gawk '$1>50 {print}'

#locate dirs which *may* be temp dirs
echo "# files bellow MAY BE temp dirs "
cat /tmp/cleanup-appdatadirs|grep -i '/\(temp\|temporary[^/]*\)$'
) > /tmp/cleanup-maybe-delete-these-$$

echo "Lists of files that were deleted were written to /tmp/cleanup*"
echo "A list of dirs that you may want to delete were written to /tmp/cleanup-maybe-delete-these-$$"

# delete temporary files
rm /tmp/rm-list
