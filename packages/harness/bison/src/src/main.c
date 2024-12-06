/* Top level entry point of Bison.

   Copyright (C) 1984, 1986, 1989, 1992, 1995, 2000-2002, 2004-2015,
   2018-2021 Free Software Foundation, Inc.

   This file is part of Bison, the GNU Compiler Compiler.

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <https://www.gnu.org/licenses/>.  */

#include <config.h>
#include "system.h"

#include <bitset.h>
#include <bitset/stats.h>
#include <closeout.h>
#include <configmake.h>
#include <progname.h>
#include <quote.h>
#include <quotearg.h>
#include <relocatable.h> /* relocate2 */
#include <timevar.h>

#include "complain.h"
#include "conflicts.h"
#include "counterexample.h"
#include "derives.h"
#include "files.h"
#include "fixits.h"
#include "getargs.h"
#include "glyphs.h"
#include "gram.h"
#include "ielr.h"
#include "lalr.h"
#include "lr0.h"
#include "muscle-tab.h"
#include "nullable.h"
#include "output.h"
#include "parse-gram.h"
#include "print-graph.h"
#include "print-xml.h"
#include "print.h"
#include "reader.h"
#include "reduce.h"
#include "scan-code.h"
#include "scan-gram.h"
#include "scan-skel.h"
#include "symtab.h"
#include "tables.h"
#include "uniqstr.h"

int
main (int argc, char *argv[])
{
  // to not break the makefile
  getargs (argc, argv);

  glyphs_init ();
  uniqstrs_new ();
  muscle_init ();
  complain_init ();
  code_scanner_init ();

#ifdef __AFL_HAVE_MANUAL_CONTROL
  __AFL_INIT();
#endif

  while (__AFL_LOOP(10000)) {

    /* Read the input.  Copy some parts of it to FGUARD, FACTION, FTABLE
      and FATTRS.  In file reader.c.  The other parts are recorded in
      the grammar; see gram.h.  */
    reader (argv[1]);

    if (complaint_status == status_complaint)
      goto finish;

    /* Find useless nonterminals and productions and reduce the grammar. */
    reduce_grammar ();

    /* Record other info about the grammar.  In files derives and
      nullable.  */
    derives_compute ();
    nullable_compute ();

    /* Compute LR(0) parser states.  See state.h for more info.  */
    generate_states ();

    /* Add lookahead sets to parser states.  Except when LALR(1) is
      requested, split states to eliminate LR(1)-relative
      inadequacies.  */
    ielr ();

    /* Find and record any conflicts: places where one token of
      lookahead is not enough to disambiguate the parsing.  In file
      conflicts.  Also resolve s/r conflicts based on precedence
      declarations.  */
    conflicts_solve ();
    if (!muscle_percent_define_flag_if ("lr.keep-unreachable-state"))
      {
        state_number *old_to_new = xnmalloc (nstates, sizeof *old_to_new);
        state_number nstates_old = nstates;
        state_remove_unreachable_states (old_to_new);
        lalr_update_state_numbers (old_to_new, nstates_old);
        conflicts_update_state_numbers (old_to_new, nstates_old);
        free (old_to_new);
      }
    if (report_flag & report_cex
        || warning_is_enabled (Wcounterexamples))
      counterexample_init ();
    conflicts_print ();

    /* Compute the parser tables.  */
    tables_generate ();

    grammar_rules_useless_report (_("rule useless in parser due to conflicts"));

    print_precedence_warnings ();

    /* Whether to generate output files.  */
    bool generate = !(feature_flag & feature_syntax_only);

    if (generate)
      {
        /* Output file names. */
        compute_output_file_names ();

        /* Output the detailed report on the grammar.  */
        if (report_flag)
          {
            print_results ();
          }

        /* Output the graph.  */
        if (graph_flag)
          {
            print_graph ();
          }

        /* Output xml.  */
        if (html_flag || xml_flag)
          {
            print_xml ();
          }

        /* Output html.  */
        if (html_flag)
          {
            print_html ();
          }
      }

    /* Stop if there were errors, to avoid trashing previous output
      files.  */
    if (complaint_status == status_complaint)
      goto finish;

    /* Lookahead tokens are no longer needed. */
    lalr_free ();

    /* Output the tables and the parser to ftable.  In file output.  */
    if (generate)
      {
        output ();
      }

  finish:

    nullable_free ();
    derives_free ();
    tables_free ();
    states_free ();
    reduce_free ();
    conflicts_free ();
    grammar_free ();
    counterexample_free ();
    output_file_names_free ();

    /* The scanner and parser memory cannot be released right after
      parsing, as it contains things such as user actions, prologue,
      epilogue etc.  */
    gram_scanner_free ();
    parser_free ();

    muscle_free ();
    code_scanner_free ();
    skel_scanner_free ();

    /* Fix input file now, even if there are errors: that's less
      warnings in the following runs.  */
    if (!fixits_empty ())
      {
        if (update_flag)
          fixits_run ();
        else
          complain (NULL, Wother,
                    _("fix-its can be applied.  Rerun with option '--update'."));
        fixits_free ();
      }
    uniqstrs_free ();

    complain_free ();
    quotearg_free ();
  }

  return complaint_status ? EXIT_FAILURE : EXIT_SUCCESS;
}
