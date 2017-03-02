//
// procdump 1.0; dumps (some) content of procfs on sunos 5.x
// unlike Linux, Solaris /proc filesystem is not in text format
// this utility allows to display content of /proc fs entries
// in user readable format
//
// Written by Antoni Sawicki <tenox@tenox.tc>
//

// todo: memory usage details

#include <sys/types.h>
#include <stdio.h>
#include <procfs.h>
#include <dirent.h>

#define BUFF 1024

int main(int argc, char *argv[]) {
	FILE *pfile;
	DIR *pdir;
	char pfname[BUFF], line[BUFF], name[32];
	char *token;
	struct dirent *direntry;
	char scall[256][32];

	// process
	struct psinfo pi;
	struct pstatus ps;
	struct prusage pu;
	struct prcred pc;
	int nfiles;

	// thread
	struct lwpsinfo li;
	struct lwpstatus ls;
	struct prusage lu;

	// argcheck
	if(argc!=2 || argv[1]==NULL) {
		fprintf(stderr, "usage: %s <pid>\n", argv[0]);
		exit(1);
	}

	// obtain list of system calls
	pfile=fopen("/usr/include/sys/syscall.h", "r");
	if(pfile!=NULL) {
		while(fgets(line, BUFF, pfile)) {
				token=(char *) strtok(line, " \t\n");
				if(token && (strcmp(token, "#define")==0)) {
					token=(char *) strtok(NULL, " \t\n");
					if(token && (strncmp(token, "SYS_", 4)==0)) {
						snprintf(name, 32, "%s", token+=4);
						token=(char *) strtok(NULL, " \t\n");
						if(token && (atoi(token)>=0) && (atoi(token)<=255)) 
							snprintf(scall[atoi(token)], 32, "%s", name);
					}
				}
		}
	}
	snprintf(scall[0], 32, "none");
	fclose(pfile);

	// psinfo
	snprintf(pfname, BUFF, "/proc/%s/psinfo", argv[1]);
	pfile=fopen(pfname, "r");
	if(pfile==NULL) {
		fprintf(stderr, "unable to open %s\n", pfname);
		exit(2);
	}
	fread(&pi, sizeof(pi), 1, pfile);
	fclose(pfile);

	// prusage
	snprintf(pfname, BUFF, "/proc/%s/usage", argv[1]);
	pfile=fopen(pfname, "r");
	if(pfile==NULL) {
		fprintf(stderr, "unable to open %s\n", pfname);
		exit(2);
	}
	fread(&pu, sizeof(pu), 1, pfile);
	fclose(pfile);

	// prcred
	snprintf(pfname, BUFF, "/proc/%s/cred", argv[1]);
	pfile=fopen(pfname, "r");
	if(pfile==NULL) {
		fprintf(stderr, "unable to open %s\n", pfname);
		exit(2);
	}
	fread(&pc, sizeof(pc), 1, pfile);
	fclose(pfile);

	// prsatus
	snprintf(pfname, BUFF, "/proc/%s/status", argv[1]);
	pfile=fopen(pfname, "r");
	if(pfile==NULL) {
		fprintf(stderr, "unable to open %s\n", pfname);
		exit(2);
	}
	fread(&ps, sizeof(ps), 1, pfile);
	fclose(pfile);

	// open files
	snprintf(pfname, BUFF, "/proc/%s/fd", argv[1]);
	pdir=opendir(pfname);
	if(pdir==NULL) {
		fprintf(stderr, "unable to open %s\n", pfname);
		exit(2);
	}
	nfiles=-2; // for . & ..
	while(readdir(pdir)) nfiles++;
	closedir(pdir);

	//
	// Format output...
	//

printf("\nBaisc Info\n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n");
	printf("  %-30s: %s\n", "File Name", pi.pr_fname);
	printf("  %-30s: %s\n", "Arguments", pi.pr_psargs);
	printf("  %-30s: %d\n", "Process ID (PID)", pi.pr_pid);
	printf("  %-30s: %d\n", "Parent Process ID (PPID)", pi.pr_ppid);
	printf("  %-30s: %d\n", "Process Group Leader ID (PGID)", pi.pr_pgid);
	printf("  %-30s: %d\n", "Session ID (SID)", pi.pr_sid);
	printf("  %-30s: ", "Process Status Flags ");
		if(ps.pr_flags & PR_STOPPED) printf("STOPPED ");
		if(ps.pr_flags & PR_ISTOP) printf("ISTOP ");
		if(ps.pr_flags & PR_DSTOP) printf("DSTOP ");
		if(ps.pr_flags & PR_STEP) printf("STEP ");
		if(ps.pr_flags & PR_ASLEEP) printf("ASLEEP ");
		if(ps.pr_flags & PR_PCINVAL) printf("PCINVAL ");
		if(ps.pr_flags & PR_ASLWP) printf("ASLWP ");
		if(ps.pr_flags & PR_AGENT) printf("AGENT ");
		if(ps.pr_flags & PR_ISSYS) printf("SYSTEM ");
		if(ps.pr_flags & PR_VFORKP) printf("VFORKP ");
		if(ps.pr_flags & PR_ORPHAN) printf("ORPHAN ");
		if(ps.pr_flags & PR_FORK) printf("FORK ");
		if(ps.pr_flags & PR_RLC) printf("RLC ");
		if(ps.pr_flags & PR_KLC) printf("KLC ");
		if(ps.pr_flags & PR_ASYNC) printf("ASYNC ");
		if(ps.pr_flags & PR_MSACCT) printf("MSACCT ");
		if(ps.pr_flags & PR_BPTADJ) printf("BPTADJ ");
		if(ps.pr_flags & PR_PTRACE) printf("PTRACE ");
		if(ps.pr_flags & PR_MSFORK) printf("MSFORK ");
	printf("(0x%08x)\n", ps.pr_flags);

	if(ps.pr_dmodel==PR_MODEL_ILP32)
		printf("  %-30s: %s\n", "Data Model", "32bit");
	else if(ps.pr_dmodel==PR_MODEL_LP64)
		printf("  %-30s: %s\n", "Data Model", "64bit");
	else if(ps.pr_dmodel==0)
		printf("  %-30s: %s\n", "Data Model", "NONE");
	else 
		printf("  %-30s: %s [0x%08x]\n", "Data Model", "Unknown", ps.pr_dmodel);

printf("\nCredentials\n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n");
	printf("  %-30s: %d\n", "Real User ID (UID)", pc.pr_ruid);
	printf("  %-30s: %d\n", "Saved User ID (SUID)", pc.pr_suid);
	printf("  %-30s: %d\n", "Effective User ID (EUID)", pc.pr_euid);
	printf("  %-30s: %d\n", "Real Group ID (GID)", pc.pr_rgid);
	printf("  %-30s: %d\n", "Saved Group ID (SGID)", pc.pr_sgid);
	printf("  %-30s: %d\n", "Effective Group ID (EGID)", pc.pr_egid);

printf("\nProcessor\n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n");
	printf("  %-30s: %3.2f %%\n", "CPU Usage", pi.pr_pctcpu * 100.0 / (float) 0x8000);
	printf("  %-30s: %d\n", "Number of LWPs", pi.pr_nlwp);
	printf("  %-30s: %c\n", "State", pi.pr_lwp.pr_sname);
	printf("  %-30s: %d\n", "Nice", ((int)pi.pr_lwp.pr_nice - 20));
	printf("  %-30s: %d\n", "Priority", pi.pr_lwp.pr_pri);
	printf("  %-30s: %d s\n", "Real Time Elapsed", pu.pr_rtime.tv_sec);
	printf("  %-30s: %d s\n", "User Level Time", pu.pr_utime.tv_sec);
	printf("  %-30s: %d s\n", "System Call Time", pu.pr_stime.tv_sec);
	printf("  %-30s: %d s\n", "I/O Wait Time", pu.pr_wtime.tv_sec);
	printf("  %-30s: %d s\n", "System Trap Time", pu.pr_ttime.tv_sec);
	printf("  %-30s: %d s\n", "Text PG Fault Time", pu.pr_tftime.tv_sec);
	printf("  %-30s: %d s\n", "Data PG Fault Time", pu.pr_dftime.tv_sec);
	printf("  %-30s: %d s\n", "Kernel PG Fault Time", pu.pr_kftime.tv_sec);
	printf("  %-30s: %d s\n", "User Lock Time", pu.pr_ltime.tv_sec);
	printf("  %-30s: %d s\n", "Other Sleep Time", pu.pr_slptime.tv_sec);
	printf("  %-30s: %d s\n", "Stopped Time", pu.pr_stoptime.tv_sec);
	printf("  %-30s: %d\n", "System Calls", pu.pr_sysc);
	printf("  %-30s: %d\n", "Voluntary Context Switches", pu.pr_vctx);
	printf("  %-30s: %d\n", "Involuntary Context Switches", pu.pr_ictx);

printf("\nMemory\n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n");
	printf("  %-30s: %3.2f %%\n", "Memory Usage", pi.pr_pctmem * 100.0 / (float) 0x8000);
	printf("  %-30s: %d KB\n", "Image Size", pi.pr_size);
	printf("  %-30s: %d KB\n", "Resident Size", pi.pr_rssize);
	printf("  %-30s: %d KB\n", "Heap Size", (int) (ps.pr_brksize/1024));
	printf("  %-30s: %d KB\n", "Stack Size", (int) (ps.pr_stksize/1024));
	printf("  %-30s: %d\n", "Swaps", pu.pr_nswap);
	printf("  %-30s: %d\n", "Minor Page Faults", pu.pr_minf);
	printf("  %-30s: %d\n", "Major Page Faults", pu.pr_majf);

printf("\nInput/Output\n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n");
	printf("  %-30s: %d\n", "Number of open files", nfiles);
	printf("  %-30s: %d KB\n", "Chars Read and Written", (int) (pu.pr_ioch/1024));
	printf("  %-30s: %d\n", "Input Blocks", pu.pr_inblk);
	printf("  %-30s: %d\n", "Output Blocks", pu.pr_oublk);
	printf("  %-30s: %d\n", "Messages Received", pu.pr_mrcv);
	printf("  %-30s: %d\n", "Messages Sent", pu.pr_msnd);
	printf("  %-30s: %d\n", "Signals Received", pu.pr_sigs);

printf("\nThreads (LWPs)\n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n");
	printf("  %-30s: %d\n", "Number of threads", pi.pr_nlwp);
	printf("  %-30s: %d\n", "Representative LWP ID", pi.pr_lwp.pr_lwpid);

	snprintf(pfname, BUFF, "/proc/%s/lwp", argv[1]);
	pdir=opendir(pfname);
	if(pdir==NULL) {
		fprintf(stderr, "unable to open %s\n", pfname);
		exit(2);
	}

	direntry=readdir(pdir);
	while(direntry) {
		if(*direntry->d_name != '.') {

			// lwpsinfo
			snprintf(pfname, BUFF, "/proc/%s/lwp/%s/lwpsinfo", argv[1], direntry->d_name);
			pfile=fopen(pfname, "r");
			if(pfile==NULL) {
				fprintf(stderr, "unable to open %s\n", pfname);
				exit(2);
			}
			fread(&li, sizeof(li), 1, pfile);
			fclose(pfile);

			/// lwpstatus
			snprintf(pfname, BUFF, "/proc/%s/lwp/%s/lwpstatus", argv[1], direntry->d_name);
			pfile=fopen(pfname, "r");
			if(pfile==NULL) {
				fprintf(stderr, "unable to open %s\n", pfname);
				exit(2);
			}
			fread(&ls, sizeof(ls), 1, pfile);
			fclose(pfile);

			// lwpusage
			snprintf(pfname, BUFF, "/proc/%s/lwp/%s/lwpusage", argv[1], direntry->d_name);
			pfile=fopen(pfname, "r");
			if(pfile==NULL) {
				fprintf(stderr, "unable to open %s\n", pfname);
				exit(2);
			}
			fread(&lu, sizeof(lu), 1, pfile);
			fclose(pfile);

			// format output...
			printf("\n   ____________________________________________\n  |\n");
			printf("  |  Basic Info\n  |  ~~~~~~~~~~~~~~~~~~~\n");
			printf("  |  %-30s: %d\n", "LWP ID", li.pr_lwpid);
			printf("  |  %-30s: %s\n", "LWP Name", li.pr_name);
			printf("  |  %-30s: ", "LWP Status Flags"); 
				if(ls.pr_flags & PR_STOPPED) printf("STOPPED ");
				if(ls.pr_flags & PR_ISTOP) printf("ISTOP ");
				if(ls.pr_flags & PR_DSTOP) printf("DSTOP ");
				if(ls.pr_flags & PR_STEP) printf("STEP ");
				if(ls.pr_flags & PR_ASLEEP) printf("ASLEEP ");
				if(ls.pr_flags & PR_PCINVAL) printf("PCINVAL ");
				if(ls.pr_flags & PR_ASLWP) printf("ASLWP ");
				if(ls.pr_flags & PR_AGENT) printf("AGENT ");
				if(ls.pr_flags & PR_ISSYS) printf("SYSTEM ");
				if(ls.pr_flags & PR_VFORKP) printf("VFORKP ");
				if(ls.pr_flags & PR_ORPHAN) printf("ORPHAN ");
				if(ls.pr_flags & PR_FORK) printf("FORK ");
				if(ls.pr_flags & PR_RLC) printf("RLC ");
				if(ls.pr_flags & PR_KLC) printf("KLC ");
				if(ls.pr_flags & PR_ASYNC) printf("ASYNC ");
				if(ls.pr_flags & PR_MSACCT) printf("MSACCT ");
				if(ls.pr_flags & PR_BPTADJ) printf("BPTADJ ");
				if(ls.pr_flags & PR_PTRACE) printf("PTRACE ");
				if(ls.pr_flags & PR_MSFORK) printf("MSFORK ");
			printf("(0x%08x)\n", ls.pr_flags);
			printf("  |  \n  |  Processor\n  |  ~~~~~~~~~~~~~~~~~~~\n");
			printf("  |  %-30s: %3.2f %%\n", "CPU Usage", li.pr_pctcpu * 100.0 / (float) 0x8000);
			printf("  |  %-30s: %c\n", "State", li.pr_sname);
			printf("  |  %-30s: %d\n", "Nice", ((int)li.pr_nice - 20));
			printf("  |  %-30s: %d\n", "Priority", li.pr_pri);
			printf("     %-30s: %s\n", "Scheduling Class", li.pr_clname);
			printf("     %-30s: %d\n", "CPU ID of last run", li.pr_onpro);
			printf("     %-30s: %d\n", "Bound to CPU ID", li.pr_bindpro);
			printf("     %-30s: %d\n", "Bound to CPU SET", li.pr_bindpset);
			printf("     %-30s: %c\n", "Sync Event Type", li.pr_stype);
			printf("     %-30s: ", "Current Syscall");
			if(scall[(int)li.pr_syscall])
				printf("%s", scall[(int)li.pr_syscall]);
			printf(" [%d]\n", (int)li.pr_syscall);
			printf("     %-30s: %d\n", "Current Signal", ls.pr_cursig); 
			printf("     %-30s: ", "Why Stopped"); 
			switch (ls.pr_why) {
				case PR_REQUESTED:; printf("REQUESTED "); break;
				case PR_SIGNALLED:; printf("SIGNALLED "); break;
				case PR_SYSENTRY:; printf("SYSENTRY "); break;
				case PR_SYSEXIT:; printf("SYSEXIT "); break;
				case PR_JOBCONTROL:; printf("JOBCONTROL "); break;
				case PR_FAULTED:; printf("FAULTED "); break;
				case PR_SUSPENDED:; printf("SUSPENDED "); break;
				case PR_CHECKPOINT:; printf("CHECKPOINT "); break;
			}
			printf("[%d]\n", ls.pr_why);
			printf("     %-30s: %d s\n", "Real Time Elapsed", lu.pr_rtime.tv_sec);
			printf("     %-30s: %d s\n", "User Level Time", lu.pr_utime.tv_sec);
			printf("     %-30s: %d s\n", "System Call Time", lu.pr_stime.tv_sec);
			printf("     %-30s: %d s\n", "I/O Wait Time", lu.pr_wtime.tv_sec);
			printf("     %-30s: %d s\n", "System Trap Time", lu.pr_ttime.tv_sec);
			printf("     %-30s: %d s\n", "Text PG Fault Time", lu.pr_tftime.tv_sec);
			printf("     %-30s: %d s\n", "Data PG Fault Time", lu.pr_dftime.tv_sec);
			printf("     %-30s: %d s\n", "Kernel PG Fault Time", lu.pr_kftime.tv_sec);
			printf("     %-30s: %d s\n", "User Lock Time", lu.pr_ltime.tv_sec);
			printf("     %-30s: %d s\n", "Other Sleep Time", lu.pr_slptime.tv_sec);
			printf("     %-30s: %d s\n", "Stopped Time", lu.pr_stoptime.tv_sec);
			printf("     %-30s: %d\n", "System Calls", lu.pr_sysc);
			printf("     %-30s: %d\n", "Voluntary Context Switches", lu.pr_vctx);
			printf("     %-30s: %d\n", "Involuntary Context Switches", lu.pr_ictx);
			printf("     \n     Memory\n     ~~~~~~~~~~~~~~~~~~~\n");
			printf("     %-30s: %d\n", "Swaps", lu.pr_nswap);
			printf("     %-30s: %d\n", "Minor Page Faults", lu.pr_minf);
			printf("     %-30s: %d\n", "Major Page Faults", lu.pr_majf);
			printf("     \n     Input/Output\n     ~~~~~~~~~~~~~~~~~~~\n");
			printf("     %-30s: %d KB\n", "Chars Read and Written", (int) (lu.pr_ioch/1024));
			printf("     %-30s: %d\n", "Input Blocks", lu.pr_inblk);
			printf("     %-30s: %d\n", "Output Blocks", lu.pr_oublk);
			printf("     %-30s: %d\n", "Messages Received", lu.pr_mrcv);
			printf("     %-30s: %d\n", "Messages Sent", lu.pr_msnd);
			printf("     %-30s: %d\n", "Signals Received", lu.pr_sigs);

		}
		free(direntry);
		direntry=readdir(pdir);
	}
	closedir(pdir);

					
	return 0;
}


// vim:ts=4:sw=4

